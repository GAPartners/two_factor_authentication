Warden::Manager.after_authentication do |user, auth, options|
  if auth.env["action_dispatch.cookies"]
    second_factor_resource_id = user.public_send(Devise.second_factor_resource_id)
    expected_cookie_value = "#{user.class}-#{second_factor_resource_id}"
    actual_cookie_value = auth.env["action_dispatch.cookies"].signed[TwoFactorAuthentication.remember_tfa_cookie_name(second_factor_resource_id)]
    bypass_by_cookie = actual_cookie_value == expected_cookie_value
  end

  if user.respond_to?(:need_two_factor_authentication?) && !bypass_by_cookie
    if auth.session(options[:scope])[TwoFactorAuthentication::NEED_AUTHENTICATION] = user.need_two_factor_authentication?(auth.request)
      user.send_new_otp if user.send_new_otp_after_login?
    end
  end
end

Warden::Manager.before_logout do |user, auth, _options|
  puts user
  puts auth
  puts _options
  second_factor_resource_id = user.public_send(Devise.second_factor_resource_id)
  auth.cookies.delete(TwoFactorAuthentication.remember_tfa_cookie_name(second_factor_resource_id)) if Devise.delete_cookie_on_logout
end
