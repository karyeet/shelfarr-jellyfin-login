require "minitest/autorun"
require "minitest/mock"
require "logger"

module Rails
  def self.application = self
  def self.config = self
  def self.to_prepare; end
  def self.logger = (@logger ||= Logger.new(IO::NULL))
end

class SettingsService
  class << self
    attr_accessor :auth_disabled
    alias_method :auth_disabled?, :auth_disabled
  end
end

require_relative "shelfarr_jellyfin_auth"

class User
  Relation = Struct.new(:users) do
    def where(**fields)
      self.class.new(users.select do |user|
        fields.all? { |key, value| Array(value).include?(user.public_send(key)) }
      end)
    end

    def active = self.class.new(users.reject(&:deleted))
    def exists?(**fields) = where(**fields).users.any?
    def find_by(**fields) = where(**fields).users.first
    def none? = users.empty?
    def limit(count) = self.class.new(users.first(count))
    def to_a = users
  end

  attr_accessor :username, :role, :oidc_provider, :oidc_uid, :deleted

  def initialize(username:, role:, oidc_provider: nil, oidc_uid: nil, **)
    @username = username
    @role = role
    @oidc_provider = oidc_provider
    @oidc_uid = oidc_uid
  end

  def self.reset! = (@users = [])
  def self.active = Relation.new(@users).active
  def self.transaction = yield
  def self.create!(**fields) = new(**fields).tap { |user| @users << user }
  def locked? = false
  def otp_enabled? = false
  def user? = role == :user
end

class SessionsController
  Request = Struct.new(:secure) do
    def ssl? = secure
  end

  attr_reader :result, :logged_in, :session, :request

  def initialize(username:, password:, provider: nil, https: true)
    @params = if provider == "jellyfin"
      { jellyfin_username: username, jellyfin_password: password, login_provider: provider }
    else
      { username: username, password: password }
    end
    @session = {}
    @request = Request.new(https)
  end

  def params = @params
  def create = (@result = :local_fallback)
  def new_session_path(**) = "/session/new"
  def sign_up_path = "/sign_up"
  def redirect_to(path, **options) = (@result = [path, options[:alert]])

  private

  def complete_login(user) = (@logged_in = user)
  def handle_failed_login(*) = (@result = :failed_login)
  def log_security_event(*) = nil
end
SessionsController.prepend(ShelfarrJellyfinSessionsOverride)

class ShelfarrJellyfinSessionsTest < Minitest::Test
  def setup
    @old_url = ENV["JELLYFIN_AUTH_URL"]
    ENV["JELLYFIN_AUTH_URL"] = "https://jellyfin.example.net"
    SettingsService.auth_disabled = false
    User.reset!
    User.create!(username: "localadmin", role: :admin)
  end

  def teardown
    ENV["JELLYFIN_AUTH_URL"] = @old_url
  end

  def remote_login(username: "Mary Jones", https: true)
    SessionsController.new(username: username, password: "fixture-password", provider: "jellyfin", https: https)
  end

  def test_local_form_never_contacts_jellyfin
    ShelfarrJellyfinAuth.stub(:authenticate, ->(**) { flunk "Unexpected remote authentication" }) do
      login = SessionsController.new(username: "localadmin", password: "local-password")
      login.create
      assert_equal :local_fallback, login.result
    end
  end

  def test_local_form_rejects_linked_and_unknown_names_the_same_way
    User.create!(username: "mary_jones", role: :user, oidc_provider: "jellyfin", oidc_uid: "a" * 32)
    ShelfarrJellyfinAuth.stub(:authenticate, ->(**) { flunk "Unexpected remote authentication" }) do
      %w[mary_jones unknown].each do |username|
        login = SessionsController.new(username: username, password: "fixture-password")
        login.create
        assert_equal :failed_login, login.result
        assert_nil login.logged_in
      end
    end
  end

  def test_first_and_repeat_logins_use_the_jellyfin_identity
    remote = { id: "a" * 32, name: "Mary Jones" }
    ShelfarrJellyfinAuth.stub(:authenticate, remote) do
      first = remote_login
      first.create
      assert_equal "mary_jones", first.logged_in.username
      assert_equal :user, first.logged_in.role
      assert_equal "jellyfin", first.logged_in.oidc_provider
      assert_equal "a" * 32, first.logged_in.oidc_uid
      second = remote_login
      second.create
      assert_same first.logged_in, second.logged_in
    end
  end

  def test_existing_hyphenated_identity_is_reused
    existing = User.create!(username: "mary_jones", role: :user, oidc_provider: "jellyfin",
      oidc_uid: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    ShelfarrJellyfinAuth.stub(:authenticate, { id: "a" * 32, name: "Mary Jones" }) do
      login = remote_login
      login.create
      assert_same existing, login.logged_in
    end
  end

  def test_same_name_cannot_sign_in_to_local_account
    ShelfarrJellyfinAuth.stub(:authenticate, { id: "b" * 32, name: "localadmin" }) do
      login = remote_login(username: "localadmin")
      login.create
      assert_nil login.logged_in
      assert_match(/can't sign in/, login.result.last)
    end
  end

  def test_deleted_local_account_releases_the_username
    deleted = User.create!(username: "mary_jones", role: :admin)
    deleted.deleted = true
    ShelfarrJellyfinAuth.stub(:authenticate, { id: "a" * 32, name: "Mary Jones" }) do
      login = remote_login
      login.create
      assert_equal "mary_jones", login.logged_in.username
      assert_equal :user, login.logged_in.role
      refute_same deleted, login.logged_in
    end
  end

  def test_deleted_jellyfin_account_can_be_provisioned_again_as_a_regular_user
    deleted = User.create!(username: "mary_jones", role: :admin, oidc_provider: "jellyfin", oidc_uid: "a" * 32)
    deleted.deleted = true
    ShelfarrJellyfinAuth.stub(:authenticate, { id: "a" * 32, name: "Mary Jones" }) do
      login = remote_login
      login.create
      assert_equal "mary_jones", login.logged_in.username
      assert_equal :user, login.logged_in.role
      refute_same deleted, login.logged_in
      assert deleted.deleted

      repeat = remote_login
      repeat.create
      assert_same login.logged_in, repeat.logged_in
    end
  end

  def test_wrong_jellyfin_password_does_not_log_in
    ShelfarrJellyfinAuth.stub(:authenticate, nil) do
      login = remote_login
      login.create
      assert_nil login.logged_in
      assert_equal "Invalid username or password.", login.result.last
    end
  end

  def test_jellyfin_credentials_require_https_on_the_shelfarr_side
    ShelfarrJellyfinAuth.stub(:authenticate, ->(**) { flunk "Unexpected remote authentication" }) do
      login = remote_login(https: false)
      login.create
      assert_match(/requires HTTPS/, login.result.last)
    end
  end

  def test_shelfarr_password_authentication_must_be_enabled
    SettingsService.auth_disabled = true
    login = SessionsController.new(username: "localadmin", password: "")
    login.create
    assert_match(/Enable Shelfarr password authentication/, login.result.last)
  end
end
