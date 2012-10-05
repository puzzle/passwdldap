#!/usr/bin/env ruby
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
 


require 'yaml'

require 'lib/passwdchange_ldap'
require 'lib/asciiart'


class PasswdApp < Sinatra::Base
  configuration = YAML.load_file 'config.yml'

  set :haml, :format => :html5
  enable :logging

  use Rack::Session::Cookie, :key => 'rack.session',
                             :secret => configuration['session_key'],
                             :expire_after => 10*60 # In seconds

  set :ldap_settings => configuration['ldap_settings']

  register Sinatra::Flash
  
  before do
    unless ldap_connection?
      halt haml :noconnection
    end
  end

  get '/' do
    set_captcha
    haml :index
  end

  post '/' do
    session[:username] = @username = params[:username]
    session[:password] = @password = params[:password]
    if valid_credentials(@username, @password, params[:captcha])
      redirect :change
    else
      redirect '/'
    end
  end

  get '/change' do
    if session[:username]
      haml :change
    else
      redirect '/'
    end
  end

  post '/change' do
    if (params["newpassword1"] == params["newpassword2"]) 
      if params["newpassword1"].length >= 8 #TODO: Improve enforcing password policy
        if change_password(session[:username], session[:password], params["newpassword1"])
          redirect '/done'
        else
          redirect '/'
        end
      else
        flash[:error] = "New Passwords too short (min. 8 chars required)"
        redirect '/change'
      end
    else
      flash[:error] = "Passwords not identical"
      redirect '/change'
    end
  end

  get '/done' do
    redirect '/' unless session[:username] 
    session.clear
    haml :done
  end

  not_found do
    haml :'404'
  end

  def set_captcha()
    a = rand(10).to_i
    b = rand(10).to_i
    session[:captcha_result] = (a + b).to_s
    @captcha = AsciiArt.random("#{a} + #{b} =")

    session[:captcha_result] = "correct" if Sinatra::Base.test?
    @captcha = AsciiArt.random("correct") if Sinatra::Base.test?
  end

  def valid_credentials(username, password, usercaptcha=nil)
    if usercaptcha == session[:captcha_result]
      if username.length > 0 # ! ldap_auth with no username is true
        ldap_authenticate(username, password)
      else
        flash[:error] = "Username not set"
        false
      end
    else
      flash[:error] = "captcha not valid"
      false
    end
  end

  def change_password(username, password, newpassword)
    with_ldap { |pwcldap| pwcldap.change_password(username, password, newpassword) }
  end

  def ldap_authenticate(username, password)
    with_ldap { |pwcldap| pwcldap.authenticate(username, password) }
  end

  def ldap_connection?
    with_ldap { |pwcldap| pwcldap.connection? }
  end

  def with_ldap
    pwcldap = PasswdChangeLdap.new(settings.ldap_settings)
    begin
      yield pwcldap
    rescue RuntimeError => msg
      flash[:error] = msg.to_s
      false
    end
  end
  
  # start the server if ruby file executed directly
  run! if app_file == $0
end
