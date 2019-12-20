import React, { Component } from 'react';
import { connect } from 'react-redux';

import { Card, CardText } from 'material-ui/Card';
import ActionCheck from 'material-ui/svg-icons/action/check-circle';
import AlertError from 'material-ui/svg-icons/alert/error-outline';
import RaisedButton from 'material-ui/RaisedButton';
import { Toolbar, ToolbarGroup } from 'material-ui/Toolbar';

import TextField from 'material-ui/TextField';

import { ViewTitle } from 'admin-on-rest';
import { showNotification } from 'admin-on-rest';
import { push } from 'react-router-redux';

import base64js from 'base64-js';

import PropTypes from 'prop-types';

import { request } from '../restClient';


class AddUserPolicy extends Component {
    constructor(props) {
        super(props);
        this.handleAddCredentialToUser = this.handleAddCredentialToUser.bind(this);
        this.handleCancel = this.handleCancel.bind(this);
    }

    getBasePath() {
        const { location } = this.props;
        return location.pathname
            .split('/')
            .slice(0, -1)
            .join('/');
    }

    componentWillMount() {
      this.setState({
        'id': '',
        'name': '',
        'isLoading': false,
        'submitting': false,
        'pristine': true,
      });
    }

    async handleAddCredentialToUser(event) {
      const { dispatch } = this.props;
      const user = this.props.match.params.user;

      const {name} = this.state;

      this.setState({'submitting': true});

      try {
        let { status, json } = await request('POST', `/users/${user}/webauthn-credentials`);
        if (status !== 200) {
          dispatch(showNotification("Unhandled server error. Please try again laster."));
          return;
        }

        let enc = new TextEncoder();
        console.log(base64js.fromByteArray(enc.encode(json.user.id)));
        let createOptions = {
          publicKey: {
            rp: json.rp,
            user: {
              id: enc.encode(json.user.id),
              displayName: json.user.displayName,
              name: json.user.name,
              // icon: json.user.icon,
            },
            challenge: enc.encode(json.challenge),
            pubKeyCredParams: [{
              type: "public-key",
              alg: -36,
            },{
              type: "public-key",
              alg: -7,
            },],
            attestation: 'direct',
            //excludeCredentials: [],
            //extensions: json.extensions,
            //timeout: json.timeout,
          }
        }

        let newCredential = await navigator.credentials.create(createOptions);
        console.log(newCredential);

        let { status: status2 } = await request('POST', `/users/${user}/webauthn-credentials/complete`, {
          name: name,
          publickey: {
            id: newCredential.id,
            type: newCredential.type,
            attObj: Array.from(new Uint8Array(newCredential.response.attestationObject)),
            clientData: Array.from(new Uint8Array(newCredential.response.clientDataJSON)),
            registrationClientExtensions: JSON.stringify(newCredential.getClientExtensionResults()),
          },
        });

        if (status2 !== 200) {
          dispatch(showNotification("Unhandled server error. Please try again laster."));
          return;
        }

        // Let the user know it worked
        dispatch(showNotification("Added Credential"));

        // Bounce back to the user detail view
        dispatch(push(this.getBasePath()));
      }
      finally {
        this.setState({'submitting': false})
      }
    }

    handleCancel() {
        this.props.history.goBack();
    }

    render() {
      return <Card>
          <ViewTitle title="Add WebAuthn Credential" />
          <CardText>
            <TextField
              floatingLabelText="Credential Name"
              hintText="Name"
              errorText=""
              value={this.state.name}
              onChange={ev => this.setState({name: ev.target.value, pristine: false})}
              />
          </CardText>
          <Toolbar>
              <ToolbarGroup>
                  <RaisedButton
                      type="submit"
                      label="Save"
                      icon={<ActionCheck />}
                      onClick={this.handleAddCredentialToUser}
                      disabled={this.state.submitting || this.state.pristine}
                      primary
                  />
                  <RaisedButton
                      label="Cancel"
                      icon={<AlertError />}
                      disabled={this.state.submitting}
                      onClick={this.handleCancel}
                  />
              </ToolbarGroup>
          </Toolbar>
      </Card>
    };
};

AddUserPolicy.propTypes = {
    dispatch: PropTypes.func.isRequired,
};

export default connect()(AddUserPolicy);
