class AddShelfarrJellyfinLastOtpAtToUsers < ActiveRecord::Migration[8.1]
  def change
    add_column :users, :shelfarr_jellyfin_last_otp_at, :bigint
  end
end
