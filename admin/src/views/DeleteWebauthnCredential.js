import React, { Component } from 'react';
import { connect } from 'react-redux';

import { Card, CardText } from 'material-ui/Card';
import ActionCheck from 'material-ui/svg-icons/action/check-circle';
import AlertError from 'material-ui/svg-icons/alert/error-outline';
import RaisedButton from 'material-ui/RaisedButton';
import { Toolbar, ToolbarGroup } from 'material-ui/Toolbar';

import { ViewTitle } from 'admin-on-rest';
import { showNotification } from 'admin-on-rest';
import { push } from 'react-router-redux';

import PropTypes from 'prop-types';

import { request } from '../restClient';


class DeleteUserCredential extends Component {
    constructor(props) {
        super(props);

        this.state = {
          'submitting': false,
        };

        this.handleDeleteCredential = this.handleDeleteCredential.bind(this);
        this.handleCancel = this.handleCancel.bind(this);
    }

    getBasePath() {
        const { location } = this.props;
        return location.pathname
            .split('/')
            .slice(0, -3)
            .join('/');
    }

    async handleDeleteCredential(event) {
      const { dispatch } = this.props;
      const { user, credential } = this.props.match.params;

      this.setState({'submitting': true});

      try {
        let { status } = await request('DELETE', `/users/${user}/webauthn-credentials/${credential}`);

        if (status === 201) {
          // Let the user know it worked
          dispatch(showNotification("Removed credential"));

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
          <ViewTitle title="Remove credential from user" />
          <CardText>Are you sure you want to remove this credential?</CardText>
          <Toolbar>
              <ToolbarGroup>
                  <RaisedButton
                      type="submit"
                      label="Delete"
                      icon={<ActionCheck />}
                      onClick={this.handleDeleteCredential}
                      disabled={this.state.submitting}
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

DeleteUserCredential.propTypes = {
    dispatch: PropTypes.func.isRequired,
};

export default connect()(DeleteUserCredential);
