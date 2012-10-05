#  | # COPYRIGHT HEADER START # 
# |   PasswdLDAP is a Sinatra App that allows users to change their OpenLDAP Password
# |   Copyright (C) 2012 Puzzle ITC GmbH www.puzzle.ch
# |   
# |   This program is free software: you can redistribute it and/or modify
# |   it under the terms of the GNU Affero General Public License as
# |   published by the Free Software Foundation, either version 3 of the
# |   License, or (at your option) any later version.
# |   
# |   This program is distributed in the hope that it will be useful,
# |   but WITHOUT ANY WARRANTY; without even the implied warranty of
# |   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# |   GNU Affero General Public License for more details.
# |   
# |   You should have received a copy of the GNU Affero General Public License
# |   along with this program.  If not, see <http://www.gnu.org/licenses/>.
# | # COPYRIGHT HEADER END # 
 

require 'net/ldap'
require 'net/ntlm'
require 'sha1'
require 'base64'


class PasswdChangeLdap
  def initialize(ldap_settings)
    @ldap_settings = ldap_settings
    @ldap = Net::LDAP.new(@ldap_settings)
  end

  def connection?
    connect
  end

  def authenticate(username, password)
    if user_dn = fetch_user_dn(username, password)
      authenticated = connect(user_dn, password)
      raise "Authentication FAILED" unless authenticated 
      authenticated
    end
  end

  def connect(user_dn=nil, password=nil)
    ldap_settings = @ldap_settings
    if (user_dn && password)
      ldap_settings = @ldap_settings.merge(
             :auth => { :method => :simple,
                        :username => user_dn,
                        :password => password, 
                      })
    end
      @ldap = Net::LDAP.new(ldap_settings)
    begin
      @ldap.bind #Throws Exception if it can't connect to server  # if !user_dn: @auth={:method=>:anonymous}
    rescue Net::LDAP::LdapError => e
      false
    end
  end

  def fetch_user_dn(username, password)
    if result = @ldap.bind_as( # find user_dn from username
      :base     => @ldap_settings[:base],
      :filter   => "uid=#{username}",
      :password => password 
      )
      result.first.dn
    else
      raise "Wrong username or password"
    end
  end

  def change_password(username, password, newpassword)
    raise "Invalid request, wrong password" unless user_dn = fetch_user_dn(username, password)
    unless connect(user_dn, password) && update_samba_password(user_dn, newpassword) && update_user_password(user_dn, newpassword)
      connect(user_dn, password) || connect(user_dn, newpassword)
      update_samba_password(user_dn, password)
      update_user_password(user_dn, password)
      raise "Error changing password, password reset"
    else
      true
    end
  end

protected
  def update_user_password(user_dn, password)
    hash = "{SSHA}" + encrypt_ssha(password)
    @ldap.replace_attribute(user_dn, "userPassword", hash)
    @ldap.get_operation_result.code == 0
  end

  def update_samba_password(user_dn, password)
    hash = Net::NTLM::ntlm_hash(password).unpack("H*").to_s.upcase
    @ldap.replace_attribute(user_dn, "sambaNTPassword", hash)
    raise "Server not authorized to change account (not master)" if @ldap.get_operation_result.code == 10
    @ldap.get_operation_result.code == 65 || @ldap.get_operation_result.code == 0 # LDAP Error code 65 means user has no sambaAccount objclass addded > no pw to be set
  end

  def encrypt_ssha(string)
    chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
    salt = chars[rand(chars.length - 1)]
    salt << chars[rand(chars.length - 1)]
    Base64.encode64(Digest::SHA1.digest(string+salt)+salt).chomp!
  end
end
