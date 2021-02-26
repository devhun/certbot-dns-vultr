#!/usr/bin/env node

const { Command } = require('commander')
const program = new Command()
const VultrNode = require('@vultr/vultr-node')

program
    .requiredOption('-k, --key <key>', 'your Vultr API Key')

const TTL = 120
const SLEEP = TTL + 30

let vultr

let domain
let validation

const sleep = ms => {
    return new Promise(resolve => {
        setTimeout(resolve, ms)
    })
}

const validationEnvironment = () => {
    let options = program.opts()
    vultr = VultrNode.initialize({
        apiKey: options.key
    })

    console.info('Vultr DNS Authenticator plugin for Certbot')
    console.info(` - APIKEY [${options.key}]`)

    domain = process.env.CERTBOT_DOMAIN
    validation = process.env.CERTBOT_VALIDATION

    console.info(` - DOMAIN : ${domain}`)
    console.info(` - VALIDATION : ${validation}`)

    if (!domain || !validation) {
        throw 'Can`t be run standalone'
    }
}

const makeAcmeChallengeName = domainName => {
    let domainPrefix = domainName === domain ? '' : domain.replace(`.${domainName}`, '')
    return `_acme-challenge${(!domainPrefix ? '' : `.${domainPrefix}`)}`
}

const getDomainList = (per_page, cursor) => {
    return new Promise(async (resolve, reject) => {
        try {
            let domains = []
            do {
                let result = await vultr.dns.listDomains({ per_page, cursor })
                if (result instanceof Error) throw result
                domains.push(...result.domains)
                cursor = result.meta.links.next
            } while(cursor !== '')
            resolve(domains.map(domain => domain.domain))
        } catch (e) {
            reject(e)
        }
    })
}

const findDomainName = (domain, domains) => {
    let dotCounts = (domain.match(/\./g) || []).length
    let domainName = domain

    for (let i=0; i<=dotCounts; i++) {
        if (domains.indexOf(domainName) >= 0) {
            return domainName
        }
        domainName = domainName.slice(domainName.indexOf('.') + 1)
    }

    throw `${domain} is not exists domain list`
}

const findTXTRecord = (domain, name, data) => {
    return new Promise(async (resolve, reject) => {
        try {
            let cursor
            let records = []
            do {
                let result = await vultr.dns.listRecords({ 'dns-domain': domain })
                if (result instanceof Error) throw result
                records.push(...result.records)
                cursor = result.meta.links.next
            } while(cursor !== '')
            resolve(records.filter(record => record.type === 'TXT' && record.name === name && record.data == data))
        } catch (e) {
            reject(e)
        }
    })
}

program
    .command('auth')
    .action(async () => {
        try {
            validationEnvironment()
            let domains = await getDomainList()
            let domainName = findDomainName(domain, domains)
            let acmeChallenge = makeAcmeChallengeName(domainName)
    
            let result = await vultr.dns.createRecord({ 'dns-domain': domainName, name: acmeChallenge, type: 'TXT', data: `"${validation}"`, ttl: TTL })
            if (result instanceof Error) throw result
            console.info(`_acme-challenge TXT record created after waiting ${SLEEP} seconds`)
            await sleep(SLEEP * 1000)
            console.info('_acme-challenge TXT record may be spread complete...')
    
            process.exit(0)
        } catch (e) {
            console.error(e)
            process.exit(1)
        }
    })

program
    .command('cleanup')
    .action(async () => {
        try {
            validationEnvironment()
            let domains = await getDomainList()
            let domainName = findDomainName(domain, domains)
            let acmeChallenge = makeAcmeChallengeName(domainName)

            let result = await findTXTRecord(domainName, acmeChallenge, `"${validation}"`)
            if (result instanceof Error) throw result
            if (result.length > 0) {
                console.info('_acme-challenge TXT record clenaup')
                for (let record of result) {
                    await vultr.dns.deleteRecord({ 'dns-domain': domainName, 'record-id': record.id })
                }
            }
        } catch (e) {
            console.error(e)
            process.exit(1)
        }
    })

program.parse(process.argv)