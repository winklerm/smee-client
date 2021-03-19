import validator = require('validator')
import EventSource = require('eventsource')
import superagent = require('superagent')
import url = require('url')
import querystring = require('querystring')
import crypto = require('crypto')

type Severity = 'info' | 'error'

interface Options {
  source: string
  target: string
  secret: string
  logger?: Pick<Console, Severity>
}

class Client {
  source: string;
  target: string;
  secret: string;
  logger: Pick<Console, Severity>;
  events!: EventSource;

  constructor ({ source, target, secret, logger = console }: Options) {
    this.source = source
    this.target = target
    this.secret = secret
    this.logger = logger!

    if (!validator.isURL(this.source)) {
      throw new Error('The provided URL is invalid.')
    }

    if (this.secret) {
      this.logger.info('Secret supplied, will recalculate signatures.')
    } else {
      this.logger.info('Secret NOT supplied, will NOT recalculate signatures.')
    }
  }

  static async createChannel () {
    return superagent.head('https://smee.io/new').redirects(0).catch((err) => {
      return err.response.headers.location
    })
  }

  sign (secret: any, blob: any) {
    var hmac
    hmac = crypto.createHmac('sha1', secret).update(Buffer.from(blob, 'utf-8')).digest('hex');
    return 'sha1=' + hmac;
  }

  sign256 (secret: any, blob: any) {
    var hmac 
    hmac = crypto.createHmac('sha256', secret).update(Buffer.from(blob, 'utf-8')).digest('hex');
    return 'sha256=' + hmac;
  }

  recalculateSignatureIfPresent (data: any) {
    const originalSignature = data["x-hub-signature"]
    const originalSignature256 = data["x-hub-signature-256"]
    const blob = JSON.stringify(data.body);

    if (originalSignature && this.secret && blob) {
      const signature = this.sign(this.secret, blob);
      const signature256 = this.sign256(this.secret, blob);

      this.logger.info(`Recalculated signature: ${originalSignature} -> ${signature}`)
      this.logger.info(`Recalculated signature 256: ${originalSignature256} -> ${signature256}`)

      data["x-hub-signature"] = signature
      data["x-hub-signature-256"] = signature256
    }
  }

  onmessage (msg: any) {
    const data = JSON.parse(msg.data)

    const target = url.parse(this.target, true)
    const mergedQuery = Object.assign(target.query, data.query)
    target.search = querystring.stringify(mergedQuery)

    delete data.query

    // Remove the host header, leaving it causes issues with SNI and TLS verification
    delete data.host

    this.recalculateSignatureIfPresent(data)

    const req = superagent.post(url.format(target)).send(data.body)

    delete data.body

    Object.keys(data).forEach(key => {
      req.set(key, data[key])
    })

    req.end((err, res) => {
      if (err) {
        this.logger.error(err)
      } else {
        this.logger.info(`${req.method} ${req.url} - ${res.status}`)
      }
    })
  }

  onopen () {
    this.logger.info('Connected', this.events.url)
  }

  onerror (err: any) {
    this.logger.error(err)
  }

  start () {
    const events = new EventSource(this.source);

    // Reconnect immediately
    (events as any).reconnectInterval = 0 // This isn't a valid property of EventSource

    events.addEventListener('message', this.onmessage.bind(this))
    events.addEventListener('open', this.onopen.bind(this))
    events.addEventListener('error', this.onerror.bind(this))

    this.logger.info(`Forwarding ${this.source} to ${this.target}`)
    this.events = events

    return events
  }
}

export = Client
