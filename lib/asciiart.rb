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
 

require 'artii'

class AsciiArt
  def self.random(text)
    fontpool= [ "char2___",
                "rectangles",
                "pawp",
                "sansi",
                "xchartri",
                "eftifont",
                "mini",
                "small",
                "big",
                "smshadow",
                "epic",
                "ogre",
                "standard",
                "univers",
                "smscript",
                "larry3d",
                "jazmine"]

    random_font = fontpool[ rand(fontpool.length).to_i ]
    artii = Artii::Base.new("-f", random_font, text )
    artii.output
  end
end
