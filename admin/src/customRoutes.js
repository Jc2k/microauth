import React from 'react';
import { Route } from 'react-router-dom';
import AddGroupToUser from './views/AddGroupToUser';
import CreateUser from './views/CreateUser';
import EditUser from './views/EditUser';
import AddUserPolicy from './views/AddUserPolicy';
import EditUserPolicy from './views/EditUserPolicy';
import DeleteUserPolicy from './views/DeleteUserPolicy';
import AddAccessKey from './views/AddAccessKey';
import DeleteAccessKey from './views/DeleteAccessKey';
import DeleteGroupMembership from './views/DeleteGroupMembership';
import AddWebauthnCredential from './views/AddWebauthnCredential';
import EditWebauthnCredential from './views/EditWebauthnCredential';
import DeleteWebauthnCredential from './views/DeleteWebauthnCredential';

import CreateGroup from './views/CreateGroup';
import EditGroup from './views/EditGroup';
import AddGroupPolicy from './views/AddGroupPolicy';
import EditGroupPolicy from './views/EditGroupPolicy';
import DeleteGroupPolicy from './views/DeleteGroupPolicy';


export default [
    <Route path="/users/:user/add-to-group" component={AddGroupToUser} />,
    <Route path="/users/:user/policies/add" component={AddUserPolicy} />,
    <Route path="/users/:user/policies/:policy/edit" component={EditUserPolicy} />,
    <Route path="/users/:user/policies/:policy/delete" component={DeleteUserPolicy} />,
    <Route path="/users/:user/keys/add" component={AddAccessKey} />,
    <Route path="/users/:user/keys/:key/delete" component={DeleteAccessKey} />,
    <Route path="/users/:user/webauthn-credentials/add" component={AddWebauthnCredential} />,
    <Route path="/users/:user/webauthn-credentials/:credential/edit" component={EditWebauthnCredential} />,
    <Route path="/users/:user/webauthn-credentials/:credential/delete" component={DeleteWebauthnCredential} />,
    <Route path="/users/:user/groups/:group/delete" component={DeleteGroupMembership} />,
    <Route path="/users/create" component={CreateUser} />,
    <Route path="/users/:user" component={EditUser} />,

    <Route path="/groups/create" component={CreateGroup} />,
    <Route path="/groups/:group/policies/add" component={AddGroupPolicy} />,
    <Route path="/groups/:group/policies/:policy/edit" component={EditGroupPolicy} />,
    <Route path="/groups/:group/policies/:policy/delete" component={DeleteGroupPolicy} />,
    <Route path="/groups/:group" component={EditGroup} />,
];
