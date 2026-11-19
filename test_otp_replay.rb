require "test_helper"

# Run in the Shelfarr checkout with the initializer enabled and migration applied.
class ShelfarrJellyfinOtpVerificationTest < ActiveSupport::TestCase
  setup do
    assert_includes User.ancestors, ShelfarrJellyfinOtpVerification
    @user = User.create!(username: "otp_replay_test", name: "OTP Test", password: "ExampleTest123!")
    @user.update!(otp_secret: "JBSWY3DPEHPK3PXP")
    @backup_codes = @user.enable_otp!
  end

  test "an authenticator code can be accepted only once across user instances" do
    travel_to(Time.utc(2026, 1, 1)) do
      code = ROTP::TOTP.new(@user.otp_secret).now
      other_instance = User.find(@user.id)

      assert @user.verify_otp(code)
      assert_not other_instance.verify_otp(code)

      travel 30.seconds
      next_code = ROTP::TOTP.new(@user.otp_secret).now
      assert other_instance.verify_otp(next_code)
    end
  end

  test "changing the secret resets authenticator code history" do
    freeze_time do
      assert @user.verify_otp(ROTP::TOTP.new(@user.otp_secret).now)
      @user.generate_otp_secret!

      assert_nil @user.reload.shelfarr_jellyfin_last_otp_at
      assert @user.verify_otp(ROTP::TOTP.new(@user.otp_secret).now)
    end
  end

  test "a backup code is consumed even for a user instance loaded earlier" do
    other_instance = User.find(@user.id)

    assert @user.verify_backup_code(@backup_codes.first)
    assert_not other_instance.verify_backup_code(@backup_codes.first)
    assert other_instance.verify_backup_code(@backup_codes.second)
    assert_equal @backup_codes.size - 2, @user.reload.backup_codes_remaining
  end
end
