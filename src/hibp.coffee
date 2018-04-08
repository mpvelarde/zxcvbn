util = require('./util')
crypto = require 'crypto'

hibp_url = "https://api.pwnedpasswords.com/range/"


checkpwd = (hash, data) ->
  lines = data.split(/\r?\n/)
  for line in lines
    hash_count = line.split(":")
    if hash.endsWith(hash_count[0])
      return hash_count[1]
  return 0

hibp =
  #-------------------------------------------------------------------------------
  # i have been pwned api check --------------------------------------------------
  #-------------------------------------------------------------------------------

  match: (password, callback) ->
    hash = @sha_str(password).toUpperCase()
    prefix = hash.substr(0, 5)

    req = https.get hibp_url + prefix, (res) ->
      status = res.statusCode
      if status == 200
        data = ''
        res.on 'data', (chunk) ->
          data += chunk.toString()
        res.on 'end', () ->
          matches = []
          count = checkpwd(hash, data)
          if count > 0
            matches.push
              pattern: 'hibp'
              count: count
          callback matches

  sha_str: (string) ->
    return crypto.createHash('sha1').update(string).digest('hex')

module.exports = hibp
