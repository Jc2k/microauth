import React, { Component } from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';

import AccessKeyList from '../ui/AccessKeyList';
import EditUserPanel from '../ui/EditUserPanel';
import GroupList from '../ui/GroupList';
import PolicyList from '../ui/PolicyList';
import WebauthCredentialsList from '../ui/WebauthCredentialsList';

class EditUser extends Component {
    render() {
      const { user } = this.props.match.params;

      return <div>
        <div><EditUserPanel user={user} /></div>
        <AccessKeyList user={user} />
        <WebauthCredentialsList user={user} />
        <GroupList user={user} />
        <PolicyList user={user} />
      </div>
    };
};

EditUser.propTypes = {
    dispatch: PropTypes.func.isRequired,
};

export default connect()(EditUser);
