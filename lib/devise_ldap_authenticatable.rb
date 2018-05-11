# encoding: utf-8
require 'devise'
require 'net/ldap'

require 'devise_ldap_authenticatable/exception'
require 'devise_ldap_authenticatable/logger'
require 'devise_ldap_authenticatable/ldap/adapter'
require 'devise_ldap_authenticatable/ldap/connection'

# Get ldap information from config/ldap.yml now
module Devise
  extend self
  # Allow logging
  mattr_accessor :ldap_logger
  @@ldap_logger = true

  # A path to YAML config file or a Proc that returns a
  # configuration hash
  mattr_accessor :ldap_config
  def self.config
    if ::Devise.ldap_config.is_a?(Proc)
      ::Devise.ldap_config.call
    else
      YAML.load(ERB.new(File.read(::Devise.ldap_config || "#{Rails.root}/config/ldap.yml")).result)[Rails.env]
    end
  end

  mattr_accessor :ldap_auth_username_builder
  @@ldap_auth_username_builder = Proc.new() {|attribute, login, ldap| "#{attribute}=#{login},#{ldap.base}" }

  mattr_accessor :ldap_auth_password_builder
  @@ldap_auth_password_builder = Proc.new() {|new_password| Net::LDAP::Password.generate(:sha, new_password) }

  def self.ldap_create_user
    config.fetch('ldap_create_user', true)
  end

  def self.ldap_check_group_membership
    config.fetch('ldap_check_group_membership', false)
  end

  def ldap_check_group_membership_without_admin
    config.fetch('ldap_check_group_membership_without_admin', false)
  end

  def ldap_check_attributes
    config.fetch('ldap_check_role_attribute', false)
  end

  def ldap_check_attributes_presence
    config.fetch('ldap_check_attributes_presence', false)
  end

  def ldap_use_admin_to_bind
    config.fetch('ldap_use_admin_to_bind', true)
  end

  def ldap_ad_group_check
    config.fetch('ldap_ad_group_check', false)
  end
end

# Add ldap_authenticatable strategy to defaults.
#
Devise.add_module(:ldap_authenticatable,
                  :route => :session, ## This will add the routes, rather than in the routes.rb
                  :strategy   => true,
                  :controller => :sessions,
                  :model  => 'devise_ldap_authenticatable/model')
