'use strict';

const _ = require('lodash');
const firebase = require('firebase-admin');
const jwt = require('jsonwebtoken');

/**
 * AuthFirebase.js controller
 *
 * @description: A set of functions called "actions" of the `auth-firebase` plugin.
 */

module.exports = {

  /**
   * Default action.
   *
   * @return {Object}
   */

  index: async (ctx) => {
    // Add your own logic here.

    // Send 200 `ok`
    ctx.send({
      message: 'ok'
    });
  },

  verify: async (ctx) => {

    // ctx.send({
    //   message: 'verify'
    // });

    if (firebase.apps.length === 0) {
      firebase.initializeApp(strapi.config.firebase);
    }
    
    const params = _.assign({}, ctx.request.body, ctx.request.query);
    // console.log(params);
    var token = null

    // strapi.plugins['users-permissions'].services.jwt.getToken(ctx);
    // copied from above - without the verify part, and the exceptions
    if (ctx.request && ctx.request.header && ctx.request.header.authorization) {
      const parts = ctx.request.header.authorization.split(' ');

      if (parts.length === 2) {
        const scheme = parts[0];
        const credentials = parts[1];
        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        }
      } else {
        // throw new Error('Invalid authorization header format. Format is Authorization: Bearer [token]');
      }
    } else if (params.token) {
      token = params.token;
    } else {
      // throw new Error('No authorization header was found');
    }

    async function verifyIdToken (token) {
      if (!token) {
        return null;
      }
      return await firebase.auth().verifyIdToken(token)
      .then(function(decodedToken) {
        return decodedToken;
      }).catch(function(error) {
        return null;
      });
    }

    const decoded = await verifyIdToken(token) || { email: null };
    const user = decoded.email ?
      await strapi.plugins['users-permissions'].models.user
        .findOne({ email: decoded.email }, ['role'])
      : null;

    console.log(decoded);

    // if null ..add to database 
    var values = {};
    if (!user && decoded.email && decoded.email.includes('@')) {

      values = {
        username: decoded.email.split('@')[0],
        email: decoded.email,
        provider: 'firebase',
        blocked: false,
        confirmed: true,
        meta: {}
      }

      console.log(decoded.firebase);
      console.log(decoded.firebase.identities);
      // return ctx.send({});

      if (values.password) {
        values.password = await strapi.plugins['users-permissions'].services.user.hashPassword(values);
      }

      const role = await strapi.plugins['users-permissions'].models.role
        .findOne({ type: 'authenticated' });

      values.role = role._id || role.id;

      // Use Content Manager business logic to handle relation.
      if (strapi.plugins['content-manager']) {
        return await strapi.plugins['content-manager'].services['contentmanager'].add({
          model: 'user'
        }, values, 'users-permissions');
      }

      user = await strapi.plugins['users-permissions'].models.user
        .findOne({ email: decoded.email }, ['role']);
    }

    if (!user) {
      return ctx.badRequest(null, ctx.request.admin ? [{ messages: [{ id: 'Auth.form.error.invalid' }] }] : 'Token invalid.');
    }

    // update identities
    let meta = {
      identities: {}
    }

    if (decoded.firebase) {
      Object.keys(decoded.firebase.identities).forEach(k => {
        let kCleaned = k.replace('.', '-');
        meta.identities[kCleaned] = decoded.firebase.identities[k];
      })
    }

    /// update
    user.meta = {
      ... user.meta,
      ... meta,
      name: decoded.name,
      photoUrl: decoded.picture
    }

    console.log(decoded);

    await strapi.plugins['users-permissions'].models.user.updateOne({
        id: user.id
      }, user);

    ctx.send({
        jwt: strapi.plugins['users-permissions'].services.jwt.issue(_.pick(user, ['_id', 'id'])),
        user: _.omit(user.toJSON ? user.toJSON() : user, ['password', 'resetPasswordToken'])
      });
  }
};
