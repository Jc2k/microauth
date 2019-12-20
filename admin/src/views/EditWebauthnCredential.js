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

import PropTypes from 'prop-types';

import { request } from '../restClient';


class EditUserPolicy extends Component {
    constructor(props) {
        super(props);

        this.state = {
          'name': '',
          'credential_id': '',
          'isLoading': true,
          'submitting': false,
          'pristine': true,
        };

        this.handleEditCredential = this.handleEditCredential.bind(this);
        this.handleCancel = this.handleCancel.bind(this);
    }

    getBasePath() {
        const { location } = this.props;
        return location.pathname
            .split('/')
            .slice(0, -3)
            .join('/');
    }

    async componentWillMount() {
      const { user, credential } = this.props.match.params;

      try {
        const response = await request('GET', `/users/${user}/webauthn-credentials/${credential}`);
        this.setState({
          'isLoading': false,
          'name': response.json.name,
        })
      } catch (e) {
        this.setState({'isLoading': false});
      }
    }

    async handleEditCredential(event) {
      const { dispatch } = this.props;
      const { user, credential: id } = this.props.match.params;
      const { name } = this.state;

      this.setState({'submitting': true});

      try {
        let { status } = await request('PUT', `/users/${user}/webauthn-credentials/${id}`, {
          name: name,
        });

        if (status === 200) {
          // Let the user know it worked
          dispatch(showNotification("Saved credential"));

          // Bounce back to the user detail view
          dispatch(push(this.getBasePath()));
        } else {
          dispatch(showNotification("Unhandled server error. Please try again laster."));
        }
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
          <ViewTitle title="Edit Policy" />
          <CardText>
              <TextField
                floatingLabelText="Name"
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
                      onClick={this.handleEditCredential}
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

EditUserPolicy.propTypes = {
    dispatch: PropTypes.func.isRequired,
};

export default connect()(EditUserPolicy);
