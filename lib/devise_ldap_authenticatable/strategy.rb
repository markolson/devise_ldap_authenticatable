require 'devise/strategies/authenticatable'

module Devise
  module Strategies
    class LdapAuthenticatable < Authenticatable

      # Tests whether the returned resource exists in the database and the
      # credentials are valid.  If the resource is in the database and the credentials
      # are valid, the user is authenticated.  Otherwise failure messages are returned
      # indicating whether the resource is not found in the database or the credentials
      # are invalid.
      def authenticate!
        resource = mapping.to.find_for_ldap_authentication(authentication_hash.merge(:password => password))

        return fail(:invalid) unless resource

        if resource.persisted?
          if validate(resource) { resource.valid_ldap_authentication?(password) }
            remember_me(resource)
            resource.after_ldap_authentication
            success!(resource)
          else
            return fail(:invalid) # Invalid credentials
          end
        end

        if resource.new_record?
          if validate(resource) { resource.valid_ldap_authentication?(password) }
            return fail(:not_found_in_database) # Valid credentials
          else
            return fail(:invalid) # Invalid credentials
          end
        end
      rescue Net::LDAP::ConnectionRefusedError => e
        DeviseLdapAuthenticatable::Logger.send("Could not connect to LDAP server; Falling back to DB")
        DeviseLdapAuthenticatable::Logger.send(e.exception)
        # TODO - what else should we do here? It may not be that their LDAP/AD is down, but that 
        # we got re-firewalled. It might do to have a healthcheck that, outside of this, pings
        # their server and binds to it using our credentials.
        return pass
      rescue DeviseLdapAuthenticatable::LdapException => else
        DeviseLdapAuthenticatable::Logger.send("Could not authenticate (?) with LDAP server; Falling back to DB")
        DeviseLdapAuthenticatable::Logger.send(e.exception)
        # Comes up when the user/auth for admin is wrong.
        return pass
      rescue Net::LDAP::Error => e
        DeviseLdapAuthenticatable::Logger.send("Could not connect to LDAP server; Falling back to DB")
        DeviseLdapAuthenticatable::Logger.send(e.exception)
        # Comes up when there's a bad hostname. Again, not sure what the actual rescue policy should
        # be because this is fairly unresolvable.
        return pass
      end
    end
  end
end

Warden::Strategies.add(:ldap_authenticatable, Devise::Strategies::LdapAuthenticatable)
