const VultrNode = require('@vultr/vultr-node')

const TTL = 120
const SLEEP = TTL + 30

const vultr = VultrNode.initialize({
  apiKey: process.env.VULTR_API_KEY
})

const sleep = (ms) => {
  return new Promise(resolve => {
    setTimeout(resolve, ms)
  })
}

const getDomainList = () => {
  return vultr.dns.list()
}

const getTXTRecords = (domain, _acme) => {
  return new Promise(async (resolve, reject) => {
    try {
      const records = await vultr.dns.records({domain})
      resolve(records.filter(record => record.type === 'TXT' && record.name === _acme))
    } catch (err) {
      reject(err)
    }
  })
}

const deleteTXTRecords = (domain, records) => {
  return new Promise(async (resolve, reject) => {
    try {
      let i = 0
      for ( ; i<records.length; i++) {
        await vultr.dns.deleteRecord({
          domain,
          RECORDID: records[i].RECORDID
        })
      }
      resolve()
    } catch (err) {
      reject(err)
    }
  })
}

const createTXTRecord = (domain, challenge, validation) => {
  return vultr.dns.createRecord({
    domain,
    name: challenge,
    type: 'TXT',
    data: '"' + validation + '"',
    ttl: TTL,
  })
}

const findDomainName = (domain, domains) => {
  let i = 0,
      j = 0
  let wordCount = (domain.match(/\./g) || []).length

  let removePrefixDomain = domain
  for ( ; i<wordCount; i++) {
    removePrefixDomain = removePrefixDomain.split('.').splice(i).join('.')
    for ( j=0; j<domains.length; j++) {
      if (domains[j].domain === removePrefixDomain) return removePrefixDomain
    }
  }
}

(async function (env) {
  console.info('Vultr DNS Authenticator plugin for Certbot\n - APIKEY [%s]', env.VULTR_API_KEY)

  if (!env.VULTR_API_KEY) {
    console.error('Require Vultr API Key')
    process.exit(1)
  }

  console.log('DOMAIN :', env.CERTBOT_DOMAIN)
  console.log('VALIDATION :', env.CERTBOT_VALIDATION)

  if (!env.CERTBOT_DOMAIN || !env.CERTBOT_VALIDATION) {
    console.error('Cannot be run standalone')
    process.exit(1)
  }

  try {
    const domains = await getDomainList()
    const domainName = findDomainName(env.CERTBOT_DOMAIN, domains)
    if (domainName === undefined) return 1

    const acmeChallenge = ('_acme-challenge.' + env.CERTBOT_DOMAIN.replace(domainName, '')).slice(0, -1)
    const records = await getTXTRecords(domainName, acmeChallenge)

    if (records.length > 1) {
      console.info('TXT records great then is 1, delete records')
      await deleteTXTRecords(domainName, records)
    }

    const result = await createTXTRecord(domainName, acmeChallenge, env.CERTBOT_VALIDATION)
    console.info('_acme-challenge TXT record created after waitting', SLEEP, 'seconds')
    await sleep(SLEEP * 1000)
    console.info('_acme-challenge TXT record may be spread complete...')

    process.exit(0)
  } catch (err) {
    console.error(err)
    process.exit(1)
  }
})(process.env)
