# Bastion
**B**reach **A**udit & **S**ecure **T**hreat **I**ntelligence for **O**pen **N**etworks

## Purpose
**Bastion** is a password audit API hosted on CloudFlare Workers, allowing you to submit a password and receive a strength score, estimated crack times, entropy, and breach status using the [zxcvbn-rs](https://github.com/shssoichiro/zxcvbn-rs) crate. This password is **never** stored, saved or logged anywhere. 

**Bastion** uses the [HaveIBeenPwned](https://haveibeenpwned.com/) database and their [k-anonymity API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) to check if your password has been included in any breaches. This involves using the first 5 characters of the SHA-1 hash being sent, not your password. 

This additional information, as opposed to *"include a symbol"* or *"capitalise a letter"*, helps provide users with more information about their password's **true** security. 

## Access
Currently, **Bastion** is available in 2 places, [RapidAPI](https://rapidapi.com/eande171-RQXKDUFxT/api/password-strength-and-breach-detection-api) and **directly**. 

The direct version **only** has a free and demo tier. The framework for a potential paid tier exists but is yet to be properly implemented. These tiers would interact with additional endpoints that **do not apply to RapidAPI** *(see 'Documentation' below for more information)*, generally offering finer control at a *hopefully* cheaper price. 

## Getting Started
You can sign up for the [RapidAPI](https://rapidapi.com/eande171-RQXKDUFxT/api/password-strength-and-breach-detection-api) version *(recommended for anything more than trying it out)*. 

Alternatively, you can also use the [demo](https://eande171.github.io/bastion/demo/) and/or register for a [native key](https://eande171.github.io/bastion/demo/#register). Registering for a key **does** require an email address, though it is hashed immediately and is **only** used if you need to regenerate your key. 

### Native Example
Here is an example of how a request would be made:
```javascript
const response = await fetch("https://bastion.eande171.workers.dev/v1/evaluate", {
  method: "POST",
  headers: {
    "Authorization": "Bearer bsn_live_...",
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ password: "hunter2" })
});

const result = await response.json();
console.log(result);
```
API keys **must** be in the `Authorization` header and **must** follow `Bearer`. 

## Security
**Bastion** applies several policies to protect all sensitive information. These include, but are not limited to:
- **Never** storing or logging passwords
- Breach checking uses the [k-anonymity API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange). **Only** the first 5 characters of a SHA1 hash are sent
- Email addresses used for regeneration and verification are hashed before storage
- All API keys and regeneration tokens are hashed before storage
- IP Addresses for the demo are hashed and after deleted after 24 hours

## Documentation
Full endpoint reference, parameters, error codes, and code examples, check out the [docs](https://eande171.github.io/bastion/docs/)!

## License
GNU AGPL v3. If you self-host a modified version, you must make your source available under the same license.
