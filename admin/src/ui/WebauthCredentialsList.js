import React, { Component } from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import {
  Table,
  TableBody,
  TableHeader,
  TableHeaderColumn,
  TableRow,
  TableRowColumn,
} from 'material-ui/Table';
import {
  Card,
  CardTitle,
  CardText,
} from 'material-ui/Card'
import { Toolbar, ToolbarGroup } from 'material-ui/Toolbar';

import ContentAdd from 'material-ui/svg-icons/content/add';
import ButtonIcon from 'material-ui/svg-icons/av/playlist-add';
import GenericButton from './GenericButton';
import RaisedButton from './RaisedButton';
import { request } from '../restClient';


class PolicyList extends Component {

  constructor(props) {
    super(props);

    this.state = {
      'isLoading': true,
      'policies': [],
    };
  }

  async componentWillMount() {
    try {
      const { user } = this.props;
      const response = await request('GET', `/users/${user}/webauthn-credentials`);
      this.setState({
        'isLoading': false,
        'policies': response.json,
      })
    } catch (e) {
      this.setState({'isLoading': false});
    }
  }

  renderInner() {
    const {isLoading, policies} = this.state;
    const { user } = this.props;

    if (isLoading) {
      return <div>Loading...</div>;
    }

    if (policies.length === 0) {
      return <div>There are no webauthn credentials attached to this user or you do not have permission to view them</div>;
    }

    return <Table selectable={false}>
      <TableHeader displaySelectAll={false}>
        <TableRow>
          <TableHeaderColumn>Name</TableHeaderColumn>
          <TableHeaderColumn>Credential Id</TableHeaderColumn>
          <TableHeaderColumn>Sign Count</TableHeaderColumn>
          <TableHeaderColumn>Actions</TableHeaderColumn>
        </TableRow>
      </TableHeader>
      <TableBody displayRowCheckbox={false}>
        {policies.map((cred) => (
          <TableRow key={cred.id}>
            <TableRowColumn>{cred.name}</TableRowColumn>
            <TableRowColumn>{cred.credential_id}</TableRowColumn>
            <TableRowColumn>{cred.sign_count}</TableRowColumn>
            <TableRowColumn>
              <GenericButton
                label="Edit"
                to={`/users/${user}/webauthn-credentials/${cred.id}/edit`}
                icon={<ButtonIcon />}
               />
               <GenericButton
                 label="Delete"
                 to={`/users/${user}/webauthn-credentials/${cred.id}/delete`}
                 icon={<ButtonIcon />}
                />
            </TableRowColumn>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  };

  render() {
    const { user } = this.props;

    return <Card style={{marginBottom: "20px"}}>
      <CardTitle title="WebAuthn Credentials" />
      <CardText>
        <div>Hardware WebAuthn public-key authentication tokens.</div>
        {this.renderInner()}
      </CardText>
      <Toolbar>
          <ToolbarGroup>
            <RaisedButton
              label="Add WebAuthn Credential"
              to={`/users/${user}/webauthn-credentials/add`}
              icon={<ContentAdd />}
              primary
             />
          </ToolbarGroup>
      </Toolbar>
    </Card>
  };
};

PolicyList.propTypes = {
  dispatch: PropTypes.func.isRequired,
};

export default connect()(PolicyList);
