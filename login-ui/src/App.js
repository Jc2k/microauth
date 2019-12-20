import React, { Component } from 'react';

import MuiThemeProvider from 'material-ui/styles/MuiThemeProvider';
import { Card, CardActions } from 'material-ui/Card';
import Avatar from 'material-ui/Avatar';
import RaisedButton from 'material-ui/RaisedButton';
import TextField from 'material-ui/TextField';
import CircularProgress from 'material-ui/CircularProgress';
import LockIcon from 'material-ui/svg-icons/action/lock-outline';
import YubikeyIcon from 'material-ui/svg-icons/device/nfc';
import { cyan500, pinkA200 } from 'material-ui/styles/colors';
import Snackbar from 'material-ui/Snackbar';
import base64js from 'base64-js';

const styles = {
    main: {
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
        alignItems: 'center',
        justifyContent: 'center',
    },
    card: {
        minWidth: 300,
    },
    avatar: {
        margin: '1em',
        textAlign: 'center ',
    },
    form: {
        padding: '0 1em 1em 1em',
    },
    input: {
        display: 'flex',
    },
    snackbar: {
      backgroundColor: pinkA200,
    }
};

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      "username": "",
      "password": "",
      "challenge": "",
      "error": "",
      "submitting": false,
      "mfa": false,
    }

    this.login = this.login.bind(this);
    this.mfaToken = this.mfaToken.bind(this);
  }

  async login(ev) {
    ev.preventDefault();

    this.setState({"submitting": true});

    const headers = new Headers({
      'Content-Type': 'application/json',
    })

    const request = {
      username: this.state.username,
      password: this.state.password,
    }

    if (this.state.mfa) {
      request.credentialId = this.state.credentialId;
      request.authenticatorData = this.state.authenticatorData;
      request.clientData = this.state.clientData;
      request.signature = this.state.signature;
    }

    try {
      const response = await fetch('/login', {
        method: "POST",
        headers: headers,
        body: JSON.stringify(request),
        credentials: 'include',
      });

      if (response.status === 200) {
        let result = await response.json();
        if ('mfa-required' in result && result['mfa-required'] === true) {
            this.setState({
              "mfa": true,
              "challenge": result['challenge'],
              "credentials": result['authenticators'],
            });
        } else {
            window.location = '/';
        }
      }
      else {
        this.setState({
          error: "It looks like we are unable to verify your username and password",
        });
        return;
      }
    }
    finally {
      this.setState({"submitting": false});
    }
  }

  async mfaToken(ev) {
    ev.preventDefault();

    let encoder = new TextEncoder();
    let attestation = await navigator.credentials.get({
      publicKey: {
        rpId: document.domain,
        challenge: encoder.encode(this.state.challenge),
        allowCredentials: this.state.credentials.map(x => ({type: "public-key", id: base64js.toByteArray(x)})),
        timeout: 60000
      }
    });

    this.setState({
      credentialId: base64js.fromByteArray(new Uint8Array(attestation.rawId)),
      authenticatorData: Array.from(new Uint8Array(attestation.response.authenticatorData)),
      clientData: Array.from(new Uint8Array(attestation.response.clientDataJSON)),
      signature: Array.from(new Uint8Array(attestation.response.signature)),
    });

    return await this.login(ev);
  }

  renderLogin() {
    return <Card style={styles.card}>
        <div style={styles.avatar}>
            <Avatar
                backgroundColor={pinkA200}
                icon={<LockIcon />}
                size={60}
            />
        </div>
        <form onSubmit={this.login}>
            <div style={styles.form}>
                <div style={styles.input}>
                    <TextField
                        name="username"
                        floatingLabelText="Username"
                        value={this.state.username}
                        onChange={ev => this.setState({username: ev.target.value})}
                        disabled={this.state.submitting}
                    />
                </div>
                <div style={styles.input}>
                    <TextField
                        name="password"
                        floatingLabelText="Password"
                        type="password"
                        value={this.state.password}
                        onChange={ev => this.setState({password: ev.target.value})}
                        disabled={this.state.submitting}
                    />
                </div>
            </div>
            <CardActions>
                <RaisedButton
                    type="submit"
                    primary
                    disabled={this.state.submitting || this.state.username.length === 0 || this.state.password.length === 0}
                    icon={
                        this.state.submitting && (
                            <CircularProgress
                                size={25}
                                thickness={2}
                            />
                        )
                    }
                    label="Signin"
                    fullWidth
                />
            </CardActions>
        </form>
    </Card>
  }

  renderMfa() {
    return <Card style={styles.card}>
        <div style={styles.avatar}>
            <Avatar
                backgroundColor={pinkA200}
                icon={<YubikeyIcon />}
                size={60}
            />
        </div>
        <form onSubmit={this.mfaToken}>
            <div style={styles.form}>
              This account has MFA enabled. Press "Signin" to active your hardware token.
            </div>
            <CardActions>
                <RaisedButton
                    type="submit"
                    primary
                    disabled={this.state.submitting}
                    icon={
                        this.state.submitting && (
                            <CircularProgress
                                size={25}
                                thickness={2}
                            />
                        )
                    }
                    label="Signin"
                    fullWidth
                />
            </CardActions>
        </form>
    </Card>
  }

  render() {
    return (
        <MuiThemeProvider>
            <div style={{ ...styles.main, backgroundColor: cyan500 }}>
                {!!this.state.mfa && this.renderMfa()}
                {!this.state.mfa && this.renderLogin()}

                <Snackbar
                  open={!!this.state.error.length}
                  message={!!this.state.error && this.state.error}
                  autoHideDuration={4000 * 4}
                  bodyStyle={styles.snackbar}
                  />
            </div>
        </MuiThemeProvider>
    );
  }
}

export default App;
