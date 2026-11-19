require "minitest/autorun"
require "minitest/mock"
require "logger"

module Rails
  def self.application = self
  def self.config = self
  def self.to_prepare; end
  def self.logger = (@logger ||= Logger.new(IO::NULL))
end
require_relative "shelfarr_jellyfin_auth"

class ShelfarrJellyfinAuthTest < Minitest::Test
  def setup
    @old_url = ENV["JELLYFIN_AUTH_URL"]
    @old_allow_private_http = ENV.delete("JELLYFIN_ALLOW_PRIVATE_HTTP")
    ENV["JELLYFIN_AUTH_URL"] = "https://jellyfin.example.net/jellyfin"
  end

  def teardown
    ENV["JELLYFIN_AUTH_URL"] = @old_url
    ENV["JELLYFIN_ALLOW_PRIVATE_HTTP"] = @old_allow_private_http
  end

  def response(code, body = "")
    result = Net::HTTPResponse::CODE_TO_OBJ.fetch(code).new("1.1", code, "test")
    result.define_singleton_method(:read_body) { |&read| read.call(body) }
    result
  end

  def with_connection(auth_response, private_address: nil)
    responses = [auth_response, response("204")]
    requests = []
    fake = Object.new
    class << fake
      attr_accessor :use_ssl, :open_timeout, :read_timeout, :write_timeout, :verify_mode, :verify_hostname, :ipaddr
      def start = yield(self)
    end
    fake.define_singleton_method(:request) do |request, &read|
      requests << request
      result = responses.shift
      read.call(result)
      result
    end
    Net::HTTP.stub(:new, ->(*arguments) do
      expected_address = private_address ? ["jellyfin", 8096, nil] : ["jellyfin.example.net", 443, nil]
      assert_equal expected_address, arguments
      fake
    end) { yield requests }
    if private_address
      refute fake.use_ssl
      assert_equal private_address, fake.ipaddr
    else
      assert fake.use_ssl
      assert fake.verify_hostname
      assert_equal OpenSSL::SSL::VERIFY_PEER, fake.verify_mode
    end
  end

  def authenticate
    ShelfarrJellyfinAuth.authenticate(username: "Mary Jones", password: "fixture-password")
  end

  def test_successful_authentication_and_token_cleanup
    payload = { User: { Id: "ABCDEF00-0000-0000-0000-000000000000", Name: "Mary Jones" }, AccessToken: "fixture-token" }
    with_connection(response("200", JSON.generate(payload))) do |requests|
      assert_equal({ id: "abcdef00000000000000000000000000", name: "Mary Jones" }, authenticate)
      login, logout = requests
      assert_equal "/jellyfin/Users/AuthenticateByName", login.path
      assert_equal({ "Username" => "Mary Jones", "Pw" => "fixture-password" }, JSON.parse(login.body))
      assert_match(/\AMediaBrowser /, login["Authorization"])
      assert_equal "/jellyfin/Sessions/Logout", logout.path
      assert_includes logout["Authorization"], 'Token="fixture-token"'
    end
  end

  def test_wrong_password
    with_connection(response("401")) do |requests|
      assert_nil authenticate
      assert_equal 1, requests.size
    end
  end

  def test_disabled_user_rejected
    payload = { User: { Id: "a" * 32, Name: "Mary Jones", Policy: { IsDisabled: true } }, AccessToken: "fixture-token" }
    with_connection(response("200", JSON.generate(payload))) do |requests|
      assert_nil authenticate
      assert_equal 2, requests.size
    end
  end

  def test_plaintext_url_is_refused_before_connecting
    ENV["JELLYFIN_AUTH_URL"] = "http://jellyfin.example.net"
    Net::HTTP.stub(:new, ->(*) { flunk "Unexpected outbound request" }) do
      assert_raises(ShelfarrJellyfinAuth::ServiceUnavailable) { authenticate }
    end
  end

  def test_private_http_resolves_the_service_name_and_pins_the_address
    ENV["JELLYFIN_AUTH_URL"] = "http://jellyfin:8096/jellyfin"
    ENV["JELLYFIN_ALLOW_PRIVATE_HTTP"] = "true"
    payload = { User: { Id: "a" * 32, Name: "Mary Jones" }, AccessToken: "fixture-token" }

    resolve = ->(host, port, _family, type, timeout:) do
      assert_equal ["jellyfin", 8096, Socket::SOCK_STREAM, 3], [host, port, type, timeout]
      [Addrinfo.ip("172.20.0.3")]
    end
    Addrinfo.stub(:getaddrinfo, resolve) do
      with_connection(response("200", JSON.generate(payload)), private_address: "172.20.0.3") do |requests|
        assert_equal({ id: "a" * 32, name: "Mary Jones" }, authenticate)
        assert_equal ["/jellyfin/Users/AuthenticateByName", "/jellyfin/Sessions/Logout"], requests.map(&:path)
      end
    end
  end

  def test_private_http_refuses_a_hostname_with_any_nonprivate_address
    ENV["JELLYFIN_AUTH_URL"] = "http://jellyfin.example.net"
    ENV["JELLYFIN_ALLOW_PRIVATE_HTTP"] = "true"
    nonprivate_addresses = ["8.8.8.8", "2001:db8::ffff:10.0.0.2", "169.254.1.1"]

    nonprivate_addresses.each do |address|
      Addrinfo.stub(:getaddrinfo, [Addrinfo.ip("172.20.0.3"), Addrinfo.ip(address)]) do
        Net::HTTP.stub(:new, ->(*) { flunk "Unexpected outbound request" }) do
          assert_raises(ShelfarrJellyfinAuth::ServiceUnavailable) { authenticate }
        end
      end
    end
  end

  def test_invalid_certificate_is_an_unavailable_service
    error = ->(*) { raise OpenSSL::SSL::SSLError, "certificate verification failed" }
    Net::HTTP.stub(:new, error) do
      assert_raises(ShelfarrJellyfinAuth::ServiceUnavailable) { authenticate }
    end
  end

  def test_oversized_response_is_rejected
    with_connection(response("200", " " * (ShelfarrJellyfinAuth::MAX_RESPONSE_BYTES + 1))) do
      assert_raises(ShelfarrJellyfinAuth::ServiceUnavailable) { authenticate }
    end
  end

  def test_username_normalization
    assert_equal "mary_jones", ShelfarrJellyfinAuth.shelfarr_username(" Mary Jones ")
    assert_nil ShelfarrJellyfinAuth.shelfarr_username("㊙️")
  end
end
