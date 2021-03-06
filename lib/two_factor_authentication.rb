require 'two_factor_authentication/version'
require 'devise'
require 'active_support/concern'
require "active_model"
require "active_support/core_ext/class/attribute_accessors"
require "cgi"

module Devise
  mattr_accessor :max_login_attempts
  @@max_login_attempts = 3

  mattr_accessor :allowed_otp_drift_seconds
  @@allowed_otp_drift_seconds = 30

  mattr_accessor :otp_length
  @@otp_length = 6

  mattr_accessor :direct_otp_length
  @@direct_otp_length = 6

  mattr_accessor :direct_otp_valid_for
  @@direct_otp_valid_for = 5.minutes

  mattr_accessor :remember_otp_session_for_seconds
  @@remember_otp_session_for_seconds = 0

  mattr_accessor :otp_secret_encryption_key
  @@otp_secret_encryption_key = ''

  mattr_accessor :second_factor_resource_id
  @@second_factor_resource_id = 'id'

  mattr_accessor :delete_cookie_on_logout
  @@delete_cookie_on_logout = false

  mattr_accessor :allow_multi_user_cookies
  @@allow_multi_user_cookies = false
end

module TwoFactorAuthentication
  NEED_AUTHENTICATION = 'need_two_factor_authentication'
  REMEMBER_TFA_COOKIE_NAME = "remember_tfa"

  def self.remember_tfa_cookie_name(id, force: false)
    if force || (Devise.allow_multi_user_cookies && id.present?)
      "#{REMEMBER_TFA_COOKIE_NAME}_#{Digest::SHA2.new(512).hexdigest(id.to_s)}"
    else
      REMEMBER_TFA_COOKIE_NAME
    end
  end

  autoload :Schema, 'two_factor_authentication/schema'
  module Controllers
    autoload :Helpers, 'two_factor_authentication/controllers/helpers'
  end
end

Devise.add_module :two_factor_authenticatable, :model => 'two_factor_authentication/models/two_factor_authenticatable', :controller => :two_factor_authentication, :route => :two_factor_authentication

require 'two_factor_authentication/orm/active_record' if defined?(ActiveRecord::Base)
require 'two_factor_authentication/routes'
require 'two_factor_authentication/models/two_factor_authenticatable'
require 'two_factor_authentication/rails'
