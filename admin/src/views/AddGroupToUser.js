import React, { Component } from 'react';
import { connect } from 'react-redux';

import { Card, CardText } from 'material-ui/Card';
import ActionCheck from 'material-ui/svg-icons/action/check-circle';
import AlertError from 'material-ui/svg-icons/alert/error-outline';
import RaisedButton from 'material-ui/RaisedButton';
import { Toolbar, ToolbarGroup } from 'material-ui/Toolbar';

import SelectField from 'material-ui/SelectField';
import MenuItem from 'material-ui/MenuItem';

import { ViewTitle } from 'admin-on-rest';
import { crudGetOne as crudGetOneAction } from 'admin-on-rest/lib/actions/dataActions';
import { showNotification } from 'admin-on-rest';
import { push } from 'react-router-redux';

import PropTypes from 'prop-types';

import { request } from '../restClient';


class AddGroupToUser extends Component {
    constructor(props) {
        super(props);

        this.state = {
          'selected': '',
          'source': [],
          'submitting': false,
          'pristine': true,
        };

        this.handleAddUserToGroup = this.handleAddUserToGroup.bind(this);
        this.handleCancel = this.handleCancel.bind(this);
    }

    getBasePath() {
        const { location } = this.props;
        return location.pathname
            .split('/')
            .slice(0, -1)
            .join('/');
    }

    async componentWillMount() {
      const { dispatch } = this.props;

      let { status, json } = await request('GET', `/groups`);
      if (status !== 200) {
        dispatch(showNotification(`Unhandled error. Server status ${status}`));
        return;
      }
      this.setState({
        'source': json,
      })
    }

    async handleAddUserToGroup(event) {
      const { dispatch } = this.props;
      const group = this.state.selected;
      const { user } = this.props.match.params;

      this.setState({'submitting': true});

      try {
        let { status } = await request('POST', `/groups/${group}/add-user`, {user: user});

        if (status === 200) {
          // Referesh the user/group data as the user should now show as being part of the group
          dispatch(crudGetOneAction("users", user));
          dispatch(crudGetOneAction("groups", group));

          // Let the user know it worked
          dispatch(showNotification("User added to group"));

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
      const { source } = this.state;

      return <Card>
          <ViewTitle title="Add User To Group" />
          <CardText>
              <SelectField
                floatingLabelText="Group"
                hintText="Group"
                errorText=""
                value={this.state.selected}
                onChange={(ev, idx, value) => this.setState({selected: value, pristine: false})}
                >
                {source.map((group) => (
                  <MenuItem key={group.id} value={group.id} primaryText={group.name} />
                ))}
                </SelectField>
          </CardText>
          <Toolbar>
              <ToolbarGroup>
                  <RaisedButton
                      type="submit"
                      label="Add"
                      icon={<ActionCheck />}
                      onClick={this.handleAddUserToGroup}
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

AddGroupToUser.propTypes = {
    dispatch: PropTypes.func.isRequired,
};

export default connect()(AddGroupToUser);
