# Passkey Server

Passkey Server provides an HTTP API for registration and login with passkeys (WebAuthn) to provide a modern 
user experience in a world beyond passwords.

Passkey Server can be used on its own or in combination with its frontend sdk or next.js integration that can be easily
integrated into any web app with as little as two lines of code.

The API is written in Go and provides the following endpoints:

* /credential - For managing already registered credentials (Listing, Updating or Removing Credentials)
* /registration - For registering new passkeys
* /login - For an authentication flow with passkeys

The detailed OpenAPI Specification can be found [here](/spec/passkey-server.yaml)

## Getting started

See the [server readme](/server/README.md) for how to get started.


## Contact us
Schedule a Hanko demo. Learn how Hanko will speed up your registration and login flows with passkeys.

<a target="_blank" href="https://cal.com/team/hanko/demo"><img alt="Book us with Cal.com"  src="https://cal.com/book-with-cal-light.svg" /></a>


## Community
### Questions, bugs, ideas
If you have any questions or issues, please check this project's [Q&A section in discussions](https://github.com/teamhanko/hanko/discussions/categories/q-a) and the [open issues](https://github.com/teamhanko/hanko/issues). Feel free to comment on existing issues or create a new issue if you encounter any bugs or have a feature request. For yet unanswered questions, feedback, or new ideas, please open a new discussion.

### Discord community & X
We invite you to join our growing [Discord community](https://www.hanko.io/community) if you want to get the latest updates on passkeys, WebAuthn, and this project, or if you just want to chat with us. You can also [follow us on Twitter](https://x.com/hanko_io).

## License

The Hanko backend ist licensed under the [GPL-3.0](LICENSE).
