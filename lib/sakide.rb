# USAGE:
# saki = Sakide.new "/path/to/key/file.des"
# cleartext = "PID=IEB0001&CRYPTO=1&MSGT=10&TRID=1234123412341234&UID=IEB00000001&LANG=HU&TS=19700101000000&AUTH=0&AMO=10000&URL=http://localhost/"
# puts "Cleartext: #{cleartext}"
# crypto = saki.encode(cleartext);
# puts "Crypted: #{crypto}"
# cleartext2 = saki.decode(crypto)
# puts "Cleartext: #{cleartext2}"

require "cgi"
require "zlib"
require "mcrypt"
require "base64"

class Sakide

  def initialize(keyfile)
    f = File.open keyfile, "r"
    keyinfo = f.read(38)
    f.close
    k1 = keyinfo[14,8]
    k2 = keyinfo[22,8] 
    @iv = keyinfo[30,8]
    @key = k1+k2+k1
  end

  def encode(plaintext)
    arr = plaintext.split '&'
    outs = ''
    pid = ''
    arr.count.times do |i|
      outs += "&#{arr[i]}" if arr[i].upcase != 'CRYPTO=1'
      pid = arr[i].upcase[4,7] if arr[i].upcase[0,4] == 'PID='
    end
    outs = outs[1..-1]
    outs = CGI.escape outs
    outs.gsub!('%3D', '=')
    outs.gsub!('%26', '&')
    crc = Zlib::crc32(outs).to_s(16).rjust(8, '0')
    4.times do |i|
      outs += crc[i*2,2].to_i(16).chr
    end
    pad = 8 - (outs.length % 8)
    pad.times do |i|
      outs += pad.chr
    end
    td = Mcrypt.new(:tripledes, :cbc, @key, @iv, '')
    outs = td.encrypt outs
    pad = 3 - (outs.length % 3)
    pad.times do |i|
      outs += pad.chr
    end
    outs = Base64.strict_encode64 outs
    outs = CGI.escape(outs) # no clue why we need strip, without that we get an extra new line
    "PID=#{pid}&CRYPTO=1&DATA=#{outs}"
  end

  def decode(crypto)
    arr = crypto.split '&'
    outs = ''
    pid = ''
    arr.count.times do |i|
      outs += arr[i][5..-1] if arr[i][0,5].upcase == 'DATA='
      pid = arr[i].upcase[4,7] if arr[i].upcase[0,4] == 'PID='
    end
    outs = CGI.unescape outs
    outs = Base64.strict_decode64 outs
    lastc = outs[-1].ord
    validpad = 1
    lastc.times do |i|
      validpad = 0 if outs[(outs.size-1-i),1].ord != lastc
    end
    outs = outs[0,(outs.size-lastc)] if validpad == 1
    td = Mcrypt.new(:tripledes, :cbc, @key, @iv, '')
    outs = td.decrypt outs
    lastc = outs[-1].ord
    validpad = 1
    lastc.times do |i|
      validpad = 0 if outs[(-1-i)].ord != lastc
    end
    outs = outs[0,(outs.size-lastc)] if validpad == 1
    crc = outs[(outs.size-4)..-1]
    crch = ''
    4.times do |i|
      crch += crc[i].ord.to_s(16).rjust(2, '0')
    end
    outs = outs[0,(outs.size-4)]
    crc = Zlib::crc32(outs).to_s(16).rjust(8, '0')
    if crch != crc
      ''
    else
      outs.gsub!('&', '%26')
      outs.gsub!('=', '%3D')
      outs = CGI.unescape(outs)
      "CRYPTO=1&#{outs}"
    end
  end
end