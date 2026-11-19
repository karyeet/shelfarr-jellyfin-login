# Mount as /rails/config/initializers/shelfarr_jellyfin_auth.rb.

require "digest"
require "ipaddr"
require "json"
require "net/http"
require "openssl"
require "securerandom"
require "uri"

module ShelfarrJellyfinAuth
  class ServiceUnavailable < StandardError; end

  PROVIDER = "jellyfin"
  MAX_RESPONSE_BYTES = 128 * 1024
  PRIVATE_HTTP_NETWORKS = %w[10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 fc00::/7 ::1/128]
    .map { |range| IPAddr.new(range) }.freeze
  CONNECTION_ERRORS = [SystemCallError, SocketError, Timeout::Error, IOError,
    Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError, OpenSSL::SSL::SSLError].freeze

  def self.configured?
    !ENV["JELLYFIN_AUTH_URL"].to_s.strip.empty?
  end

  def self.authenticate(username:, password:)
    return nil unless username.is_a?(String) && password.is_a?(String)
    return nil unless username.valid_encoding? && password.valid_encoding?
    return nil if username.empty? || password.empty? || username.bytesize > 256 || password.bytesize > 8192

    base = URI.parse(ENV["JELLYFIN_AUTH_URL"].to_s.strip)
    unless base.is_a?(URI::HTTP) && base.host && base.userinfo.nil? && base.query.nil? && base.fragment.nil?
      raise ServiceUnavailable, "JELLYFIN_AUTH_URL must be an HTTP or HTTPS base URL"
    end
    base.path = "#{base.path.chomp('/')}/"

    private_address = private_http_address(base) unless base.is_a?(URI::HTTPS)
    http = Net::HTTP.new(base.hostname, base.port, nil)
    if private_address
      http.ipaddr = private_address
    else
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.verify_hostname = true
    end
    http.open_timeout = 3
    http.read_timeout = 5
    http.write_timeout = 3

    device_id = "shelfarr-jellyfin-#{Digest::SHA256.hexdigest(username.downcase)[0, 16]}"
    client_header = "MediaBrowser Client=\"Shelfarr\", Device=\"Shelfarr\", DeviceId=\"#{device_id}\", Version=\"1.0\""
    request = Net::HTTP::Post.new(base.merge("Users/AuthenticateByName"), {
      "Authorization" => client_header, "Content-Type" => "application/json",
      "Accept" => "application/json", "Accept-Encoding" => "identity"
    })
    request.body = JSON.generate(Username: username, Pw: password)
    response, body = exchange(http, request)
    return nil if %w[401 403].include?(response.code)
    raise ServiceUnavailable, "Jellyfin authentication HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    payload = JSON.parse(body)
    raise ServiceUnavailable, "Invalid Jellyfin authentication response" unless payload.is_a?(Hash)

    token = payload["AccessToken"]
    unless token.is_a?(String) && token.bytesize <= 256 && token.match?(/\A[A-Za-z0-9_.-]+\z/)
      raise ServiceUnavailable, "Invalid Jellyfin access token"
    end
    logout(http, base, client_header, token)

    user = payload["User"]
    id = user["Id"] if user.is_a?(Hash)
    name = user["Name"] if user.is_a?(Hash)
    unless id.is_a?(String) && id.match?(/\A(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\z/i) &&
        name.is_a?(String) && name.valid_encoding? && !name.strip.empty? && name.bytesize <= 256 && !name.match?(/[[:cntrl:]]/)
      raise ServiceUnavailable, "Invalid Jellyfin user identity"
    end
    return nil if user["Policy"].is_a?(Hash) && user["Policy"]["IsDisabled"] == true

    { id: id.delete("-").downcase, name: name }
  rescue JSON::ParserError, JSON::GeneratorError, URI::Error => e
    raise ServiceUnavailable, "Invalid Jellyfin response or URL (#{e.class})"
  rescue *CONNECTION_ERRORS => e
    raise ServiceUnavailable, "Jellyfin connection failed (#{e.class})"
  end

  def self.private_http_address(base)
    unless ENV["JELLYFIN_ALLOW_PRIVATE_HTTP"] == "true"
      raise ServiceUnavailable, "Jellyfin HTTP requires JELLYFIN_ALLOW_PRIVATE_HTTP=true"
    end

    addresses = Addrinfo.getaddrinfo(base.hostname, base.port, nil, Socket::SOCK_STREAM, timeout: 3)
    unless addresses.any? && addresses.all? { |address| private_http_ip?(address.ip_address) }
      raise ServiceUnavailable, "Jellyfin HTTP requires a private or loopback address"
    end

    # Connect to the address we checked and retain the configured hostname for HTTP routing.
    addresses.first.ip_address
  end
  private_class_method :private_http_address

  def self.private_http_ip?(address)
    ip = IPAddr.new(address)
    ip = ip.native if ip.ipv4_mapped?
    PRIVATE_HTTP_NETWORKS.any? { |network| network.include?(ip) }
  end
  private_class_method :private_http_ip?

  def self.exchange(http, request)
    body = +"".b
    response = http.start do |connection|
      connection.request(request) do |result|
        result.read_body do |chunk|
          if body.bytesize + chunk.bytesize > MAX_RESPONSE_BYTES
            raise ServiceUnavailable, "Jellyfin response is too large"
          end
          body << chunk
        end
      end
    end
    [response, body]
  end
  private_class_method :exchange

  def self.logout(http, base, client_header, token)
    request = Net::HTTP::Post.new(base.merge("Sessions/Logout"), {
      "Authorization" => "#{client_header}, Token=\"#{token}\"", "Accept-Encoding" => "identity"
    })
    response, = exchange(http, request)
    unless response.is_a?(Net::HTTPSuccess)
      Rails.logger.warn "[Jellyfin login] Session logout returned HTTP #{response.code}"
    end
  rescue ServiceUnavailable, *CONNECTION_ERRORS => e
    Rails.logger.warn "[Jellyfin login] Session logout unavailable (#{e.class})"
  end
  private_class_method :logout

  def self.shelfarr_username(name)
    value = name.downcase.gsub(/[^a-z0-9_]/, "_").gsub(/\A_+|_+\z/, "")[0, 48]
    value unless value.empty?
  end
end

module ShelfarrJellyfinOtpVerification
  def verify_otp(code)
    with_lock do
      next false if deleted? || locked? || otp_secret.blank?

      totp = ROTP::TOTP.new(otp_secret)
      verified_at = totp.verify(code, drift_behind: 30, drift_ahead: 30, after: shelfarr_jellyfin_last_otp_at)
      next false unless verified_at

      update_column(:shelfarr_jellyfin_last_otp_at, verified_at)
    end
  end

  def verify_backup_code(code)
    with_lock do
      next false if deleted? || locked? || !otp_enabled?

      super(code)
    end
  end

  private

  def reset_shelfarr_jellyfin_last_otp_at
    self.shelfarr_jellyfin_last_otp_at = nil
  end
end

module ShelfarrJellyfinSessionsOverride
  PROVIDER = ShelfarrJellyfinAuth::PROVIDER
  OTP_TIMEOUT = 5 * 60
  OTP_EXPIRATION_KEY = :shelfarr_jellyfin_otp_expires_at

  def new
    super
    return if performed? || !ShelfarrJellyfinAuth.configured?

    render "sessions/shelfarr_jellyfin"
  end

  def create
    return super unless ShelfarrJellyfinAuth.configured?

    clear_pending_otp
    if SettingsService.auth_disabled?
      return redirect_to new_session_path, alert: "Enable Shelfarr password authentication to sign in."
    end

    jellyfin = params[:login_provider] == PROVIDER
    username = params[jellyfin ? :jellyfin_username : :username]
    password = params[jellyfin ? :jellyfin_password : :password]
    return handle_failed_login(nil, nil) unless username.is_a?(String) && username.valid_encoding? && password.is_a?(String)

    username = username.strip
    unless jellyfin
      user = User.active.find_by(username: username.downcase)
      return handle_failed_login(nil, username) if user.nil? || user.oidc_provider == PROVIDER

      return super
    end

    unless request.ssl?
      return redirect_to new_session_path, alert: "Jellyfin sign-in requires HTTPS."
    end
    if User.active.none?
      return redirect_to sign_up_path, alert: "Create your local Shelfarr administrator first."
    end

    jellyfin_user = ShelfarrJellyfinAuth.authenticate(username: username, password: password)
    unless jellyfin_user
      log_security_event("login.failed", nil, username)
      return redirect_to jellyfin_login_path, alert: "Invalid username or password."
    end

    user = jellyfin_shelfarr_user(jellyfin_user)
    unless user
      return redirect_to jellyfin_login_path,
        alert: "This Jellyfin account can't sign in. Contact your Shelfarr administrator."
    end

    if user.locked?
      log_security_event("login.blocked_locked", user, username)
      redirect_to jellyfin_login_path, alert: "Account is locked. Try again later."
    elsif user.otp_enabled?
      request.session_options[:secure] = true
      session[:pending_user_id] = user.id
      session[OTP_EXPIRATION_KEY] = Time.current.to_i + OTP_TIMEOUT
      redirect_to verify_otp_session_path
    else
      complete_login(user)
    end
  rescue ShelfarrJellyfinAuth::ServiceUnavailable => e
    Rails.logger.warn "[Jellyfin login] Authentication unavailable: #{e.message}"
    redirect_to jellyfin_login_path, alert: "Jellyfin authentication is unavailable. Try again later."
  end

  def verify_otp
    super if valid_pending_otp?
  end

  def submit_otp
    return unless valid_pending_otp?

    super
    session.delete(OTP_EXPIRATION_KEY) unless session[:pending_user_id]
  end

  def destroy
    clear_pending_otp if session[OTP_EXPIRATION_KEY]
    super
  end

  private

  # Shelfarr's built-in password errors redirect to this route.
  def new_session_path(*args, **options)
    return super unless args.empty? && options.empty? && action_name == "create" &&
      ShelfarrJellyfinAuth.configured? && params[:login_provider] != PROVIDER

    super(local: 1)
  end

  def jellyfin_login_path
    new_session_path(login_provider: PROVIDER, local: 1)
  end

  def jellyfin_shelfarr_user(identity)
    id = identity.fetch(:id)
    # Previous installs might have stored an ID with hyphens.
    legacy_id = [id[0, 8], id[8, 4], id[12, 4], id[16, 4], id[20, 12]].join("-")

    User.transaction do
      existing = User.active.where(oidc_provider: PROVIDER, oidc_uid: [id, legacy_id]).limit(2).to_a
      next existing.first if existing.one?
      next if existing.any? || User.active.none?

      username = ShelfarrJellyfinAuth.shelfarr_username(identity.fetch(:name))
      next if username.nil? || User.active.exists?(username: username)

      user = User.create!(username: username, name: identity.fetch(:name), password: SecureRandom.hex(32),
        role: :user, oidc_provider: PROVIDER, oidc_uid: id)
      # Shelfarr promotes the first active user during its model callback.
      raise ActiveRecord::Rollback unless user.user?

      user
    end
  rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique, ActiveRecord::LockWaitTimeout => e
    Rails.logger.warn "[Jellyfin login] Account provisioning unavailable (#{e.class})"
    nil
  end

  def valid_pending_otp?
    pending_id = session[:pending_user_id]
    expires_at = session[OTP_EXPIRATION_KEY]
    return true unless expires_at || (pending_id && User.active.exists?(id: pending_id, oidc_provider: PROVIDER))

    user = User.active.find_by(id: pending_id, oidc_provider: PROVIDER)
    if ShelfarrJellyfinAuth.configured? && request.ssl? && !SettingsService.auth_disabled? &&
        expires_at.is_a?(Integer) && expires_at > Time.current.to_i && user&.otp_enabled? && !user.locked?
      request.session_options[:secure] = true
      return true
    end

    clear_pending_otp
    redirect_to jellyfin_login_path, alert: "Sign in again to verify your Jellyfin account."
    false
  end

  def clear_pending_otp
    session.delete(:pending_user_id)
    session.delete(OTP_EXPIRATION_KEY)
  end

  def start_new_session_for(user)
    super.tap do |shelfarr_session|
      if user.oidc_provider == PROVIDER
        cookies.signed[:session_id] = {
          value: shelfarr_session.id,
          expires: SettingsService.get(:session_max_age_days, default: 30).days.from_now,
          httponly: true, same_site: :lax, secure: true
        }
      end
    end
  end
end

Rails.application.config.to_prepare do
  if ShelfarrJellyfinAuth.configured? && !User.ancestors.include?(ShelfarrJellyfinOtpVerification)
    User.prepend(ShelfarrJellyfinOtpVerification)
    User.before_save :reset_shelfarr_jellyfin_last_otp_at, if: :will_save_change_to_otp_secret?
  end

  unless SessionsController.ancestors.include?(ShelfarrJellyfinSessionsOverride)
    SessionsController.prepend(ShelfarrJellyfinSessionsOverride)
    SessionsController.rate_limit to: 10, within: ShelfarrJellyfinSessionsOverride::OTP_TIMEOUT,
      only: :submit_otp, name: "jellyfin-otp", by: -> { session[:pending_user_id] },
      if: -> { session[:shelfarr_jellyfin_otp_expires_at].is_a?(Integer) },
      with: -> { redirect_to verify_otp_session_path, alert: "Too many verification attempts. Try again later." }
  end
end
