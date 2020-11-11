Warden::Manager.after_authentication do |user, auth, options|
  if auth.env["action_dispatch.cookies"]
    second_factor_resource_id = user.public_send(Devise.second_factor_resource_id)
    expected_cookie_value = "#{user.class}-#{second_factor_resource_id}"

    actual_cookie_value = auth.env["action_dispatch.cookies"].signed[TwoFactorAuthentication.remember_tfa_cookie_name(second_factor_resource_id)] ||
                          user.decrypt_api_token(auth.request.get_header("X-2FA-ID"))&.split(':::')
                          
    bypass_by_cookie = actual_cookie_value == expected_cookie_value ||
                        (actual_cookie_value.present? &&
                        actual_cookie_value.first == TwoFactorAuthentication.remember_tfa_cookie_name(second_factor_resource_id) &&
                        actual_cookie_value.last.to_datetime < Time.now.utc)

    unless bypass_by_cookie
      if Devise.allow_multi_user_cookies && auth.env["action_dispatch.cookies"].key?(TwoFactorAuthentication::REMEMBER_TFA_COOKIE_NAME)
        actual_cookie_value = auth.env["action_dispatch.cookies"].signed[TwoFactorAuthentication::REMEMBER_TFA_COOKIE_NAME]
        bypass_by_cookie = actual_cookie_value == expected_cookie_value
      elsif !Devise.allow_multi_user_cookies && auth.env["action_dispatch.cookies"].key?(TwoFactorAuthentication.remember_tfa_cookie_name(second_factor_resource_id, force: true))
        actual_cookie_value = auth.env["action_dispatch.cookies"].signed[TwoFactorAuthentication.remember_tfa_cookie_name(second_factor_resource_id, force: true)]
        bypass_by_cookie = actual_cookie_value == expected_cookie_value
      end
    end
  end

  if user.respond_to?(:need_two_factor_authentication?) && !bypass_by_cookie
    if auth.session(options[:scope])[TwoFactorAuthentication::NEED_AUTHENTICATION] = user.need_two_factor_authentication?(auth.request)
      user.send_new_otp if user.send_new_otp_after_login?
    end
  end
end

Warden::Manager.prepend_before_logout do |user, auth, _options|
  if Devise.delete_cookie_on_logout
    auth.cookies.delete(TwoFactorAuthentication::REMEMBER_TFA_COOKIE_NAME)
    auth.cookies.delete(TwoFactorAuthentication.remember_tfa_cookie_name(user&.public_send(Devise.second_factor_resource_id), force: true))
  end
end
