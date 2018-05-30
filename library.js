(function(module) {
	"use strict";
	/* globals require, module */

	var User = module.parent.require('./user'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		passport = module.parent.require('passport'),
		passportVK = require('passport-vkontakte').Strategy,
		nconf = module.parent.require('nconf'),
		async = module.parent.require('async'),
		winston = module.parent.require('winston');

	var authenticationController = module.parent.require('./controllers/authentication');

	var constants = Object.freeze({
		'name': "Vkontakte",
		'admin': {
			'icon': 'fa-vk',
			'route': '/plugins/sso-vkontakte'
		}
	});

	var Vkontakte = {};

	Vkontakte.getStrategy = function(strategies, callback) {
		meta.settings.get('sso-vkontakte', function(err, settings) {
			Vkontakte.settings = settings;

			if (!err && settings.id && settings.secret) {
				passport.use(new passportVK({
					clientID: settings.id,
					clientSecret: settings.secret,
					callbackURL: nconf.get('url') + '/auth/vk/callback',
					passReqToCallback: true,
					scope: [ 'user:email' ] // fetches non-public emails as well
				}, function(req, token, tokenSecret, params, profile, done) {
					if (req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && req.user.uid > 0) {
						// Save Vkontakte -specific information to the user
						User.setUserField(req.user.uid, 'vkontakteid', profile.id);
						db.setObjectField('vkontakteid:uid', profile.id, req.user.uid);
						return done(null, req.user);
					}

					var email = Array.isArray(params.emails) && params.emails.length ? params.emails[0].value : '';
					Vkontakte.login(profile.id, profile.username, email, profile._json.avatar_url, function(err, user) {
						if (err) {
							return done(err);
						}

						authenticationController.onSuccessfulLogin(req, user.uid);
						done(null, user);
					});
				}));

				strategies.push({
					name: 'vkontakte',
					url: '/auth/vk',
					callbackURL: '/auth/vk/callback',
					icon: constants.admin.icon,
					scope: 'user:email'
				});
			}

			callback(null, strategies);
		});
	};

	Vkontakte.init = function(params, callback) {
		var hostHelpers = require.main.require('./src/routes/helpers');
		function render(req, res) {
			res.render('admin/plugins/sso-vkontakte', {});
		}

		params.router.get('/admin/plugins/sso-vkontakte', params.middleware.admin.buildHeader, render);
		params.router.get('/api/admin/plugins/sso-vkontakte', render);

		hostHelpers.setupPageRoute(params.router, '/deauth/vkontakte', params.middleware, [params.middleware.requireUser], function (req, res) {
			res.render('plugins/sso-vkontakte/deauth', {
				service: "Vkontakte",
			});
		});
		params.router.post('/deauth/vk', [params.middleware.requireUser, params.middleware.applyCSRF], function (req, res, next) {
			Vkontakte.deleteUserData({
				uid: req.user.uid,
			}, function (err) {
				if (err) {
					return next(err);
				}

				res.redirect(nconf.get('relative_path') + '/me/edit');
			});
		});

		callback();
	};



	Vkontakte.appendUserHashWhitelist = function (data, callback) {
		data.whitelist.push('vkontakteid');//death remember
		return setImmediate(callback, null, data);
	};

	Vkontakte.getAssociation = function(data, callback) {
		User.getUserField(data.uid, 'vkontakteid', function(err, vkontakteID) {
			if (err) {
				return callback(err, data);
			}

			if (vkontakteID) {
				data.associations.push({
					associated: true,
					//url: 'https://vk.com/' + vkontakteId,
					deauthUrl: nconf.get('url') + '/deauth/vk',
					name: constants.name,
					icon: constants.admin.icon
				});
			} else {
				data.associations.push({
					associated: false,
					url: nconf.get('url') + '/auth/vk',
					name: constants.name,
					icon: constants.admin.icon
				});
			}

			callback(null, data);
		})
	};

	Vkontakte.login = function(vkontakteID, username, displayName, email, accessToken, refreshToken, picture, callback) {

		if (!email) {
			email = username + '@vk.com';
		}


		Vkontakte.getUidByvkontakteID = function(vkontakteID, callback) {
			db.getObjectField('vkontakteid:uid', vkontakteID, function(err, uid) {
				if (err) {
					callback(err);
				} else {
					// New User
					var success = function(uid) {
						// trust vk's email
						User.setUserField(uid, 'email:confirmed', 1);
						db.sortedSetRemove('users:notvalidated', uid);

						User.setUserField(uid, 'vkontakteid', vkontakteID);

						// set profile picture
						User.setUserField(uid, 'uploadedpicture', avatar_url);
						User.setUserField(uid, 'picture', avatar_url);

						db.setObjectField('vkontakteid:uid', vkontakteID, uid);
						callback(null, {
							uid: uid
						});
					};
				}
			});
		};
	};

	Vkontakte.getUidByvkontakteID = function(vkontakteid, callback) {
		db.getObjectField('vkontakteid:uid', vkontakteid, function(err, uid) {
			if (err) {
				return callback(err);
			} else {
				return callback(null, uid);
			}
		});
	};

	Vkontakte.addMenuItem = function(custom_header, callback) {
		custom_header.authentication.push({
			'route': constants.admin.route,
			'icon': constants.admin.icon,
			'name': constants.name
		});

		callback(null, custom_header);
	};

	Vkontakte.deleteUserData = function(uid, callback) {
		async.waterfall([
			async.apply(User.getUserField, uid, 'vkontakteid'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField('vkontakteid:uid', oAuthIdToDelete, next);
			},
			function (next) {
				db.deleteObjectField('user:' + uid, 'vkontakteid', next);
			},
		], function(err) {
			if (err) {
				winston.error('[sso-vkontakte] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err);
				return callback(err);
			}
			callback(null, uid);
		});
	};

	module.exports = Vkontakte;
}(module));
