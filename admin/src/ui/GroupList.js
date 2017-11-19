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


class GroupList extends Component {

  constructor(props) {
    super(props);

    this.state = {
      'isLoading': true,
      'groups': [],
    };
  }

  async componentWillMount() {
    this.setState({'isLoading': false});
  }

  renderInner() {
    const {isLoading, groups} = this.state;

    if (isLoading) {
      return <div>Loading...</div>;
    }

    if (groups.length === 0) {
      return <div>This user is in no groups.</div>;
    }

    return <Table selectable={false}>
      <TableHeader displaySelectAll={false}>
        <TableRow>
          <TableHeaderColumn>Name</TableHeaderColumn>
          <TableHeaderColumn>Actions</TableHeaderColumn>
        </TableRow>
      </TableHeader>
      <TableBody displayRowCheckbox={false}>
        {groups.map((group) => (
          <TableRow key={group.name}>
            <TableRowColumn>{group.name}</TableRowColumn>
            <TableRowColumn>
              <GenericButton
                label="Edit"
                to={`/users/${this.props.record.id}/groups/${group.id}/edit`}
                icon={<ButtonIcon />}
               />
               <GenericButton
                 label="Delete"
                 to={`/users/${this.props.record.id}/groups/${group.id}/delete`}
                 icon={<ButtonIcon />}
                />
            </TableRowColumn>
          </TableRow>
        ))}
      </TableBody>
    </Table>

  }

  render() {
    const { user } = this.props;

    return <Card style={{marginBottom: "20px"}}>
      <CardTitle title="Groups" />
      <CardText>{this.renderInner()}</CardText>
      <Toolbar>
          <ToolbarGroup>
            <RaisedButton
              label="Add to group"
              to={`/users/${user}/add-to-group`}
              icon={<ContentAdd />}
              primary
             />
          </ToolbarGroup>
      </Toolbar>
    </Card>
  };
};

GroupList.propTypes = {
  dispatch: PropTypes.func.isRequired,
};

export default connect()(GroupList);