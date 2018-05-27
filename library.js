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

	var Vkontakte = {
		settings: undefined
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
		params.router.post('/deauth/vkontakte', [params.middleware.requireUser, params.middleware.applyCSRF], function (req, res, next) {
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

	Vkontakte.getSettings = function(callback) {
		if (Vkontakte.settings) {
			return callback();
		}

		meta.settings.get('sso-vkontakte', function(err, settings) {
			Vkontakte.settings = settings;
			callback();
		});
	};

	Vkontakte.getStrategy = function(strategies, callback) {
		if (!Vkontakte.settings) {
			return Vkontakte.getSettings(function() {
				Vkontakte.getStrategy(strategies, callback);
			});
		}

		if (
			Vkontakte.settings !== undefined
			&& Vkontakte.settings.hasOwnProperty('app_id') && Vkontakte.settings.app_id
			&& Vkontakte.settings.hasOwnProperty('secret') && Vkontakte.settings.secret
		) {
			passport.use(new passportVK({
				clientID: Vkontakte.settings.app_id,
				clientSecret: Vkontakte.settings.secret,
				callbackURL: nconf.get('url') + '/auth/vkontakte/callback',
				passReqToCallback: true,
				profileFields: ['id', 'emails', 'name', 'displayName']
			}, function(req, accessToken, refreshToken, profile, done) {
				if (req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && req.user.uid > 0) {
					// User is already logged-in, associate fb account with uid if account does not have an existing association
					User.getUserField(req.user.uid, 'vkontakteid', function (err, fbid) {
						if (err) {
							return done(err);
						}

						if (!vkontakteid || profile.id === vkontakteid) {
							User.setUserField(req.user.uid, 'vkontakteid', profile.id);
							db.setObjectField('vkontakteid:uid', profile.id, req.user.uid);
							done(null, req.user);
						} else {
							done(new Error('[[error:sso-multiple-association]]'));
						}
					});
				} else {
					var email;
					if (profile._json.hasOwnProperty('email')) {
						email = profile._json.email;
					} else {
						email = (profile.username ? profile.username : profile.id) + '@vk.com';
					}

					Vkontakte.login(profile.id, profile.displayName, email, accessToken, refreshToken, profile, function(err, user) {
						if (err) {
							return done(err);
						}

						// Require collection of email
						if (email.endsWith('@vk.com')) {
							req.session.registration = req.session.registration || {};
							req.session.registration.uid = user.uid;
							req.session.registration.vkontakteid = profile.id;
						}

						authenticationController.onSuccessfulLogin(req, user.uid, function (err) {
							done(err, !err ? user : null);
						});
					});
				}
			}));

			strategies.push({
				name: 'vkontakte',
				url: '/auth/vkontakte',
				callbackURL: '/auth/vkontakte/callback',
				icon: constants.admin.icon,
				scope: 'public_profile, email'
			});
		}

		callback(null, strategies);
	};

	Vkontakte.appendUserHashWhitelist = function (data, callback) {
		data.whitelist.push('vkontakteid');//death remember
		return setImmediate(callback, null, data);
	};

	Vkontakte.getAssociation = function(data, callback) {
		User.getUserField(data.uid, 'vkontakteid', function(err, vkontakteId) {
			if (err) {
				return callback(err, data);
			}

			if (vkontakteId) {
				data.associations.push({
					associated: true,
					url: 'https://vk.com/' + vkontakteId,
					deauthUrl: nconf.get('url') + '/deauth/vkontakte',
					name: constants.name,
					icon: constants.admin.icon
				});
			} else {
				data.associations.push({
					associated: false,
					url: nconf.get('url') + '/auth/vkontakte',
					name: constants.name,
					icon: constants.admin.icon
				});
			}

			callback(null, data);
		})
	};

	Vkontakte.prepareInterstitial = function(data, callback) {
		// Only execute if:
		//   - uid and vkontakteid are set in session
		//   - email ends with "@vk.com"
		if (data.userData.hasOwnProperty('uid') && data.userData.hasOwnProperty('vkontakteid')) {
			User.getUserField(data.userData.uid, 'email', function(err, email) {
				if (email && email.endsWith('@vk.com')) {
					data.interstitials.push({
						template: 'partials/sso-vkontakte/email.tpl',
						data: {},
						callback: Vkontakte.storeAdditionalData
					});
				}

				callback(null, data);
			});
		} else {
			callback(null, data);
		}
	};

	Vkontakte.storeAdditionalData = function(userData, data, callback) {
		async.waterfall([
			// Reset email confirm throttle
			async.apply(db.delete, 'uid:' + userData.uid + ':confirm:email:sent'),
			async.apply(User.getUserField, userData.uid, 'email'),
			function (email, next) {
				// Remove the old email from sorted set reference
				db.sortedSetRemove('email:uid', email, next);
			},
			async.apply(User.setUserField, userData.uid, 'email', data.email),
			async.apply(User.email.sendValidationEmail, userData.uid, data.email)
		], callback);
	};

	Vkontakte.storeTokens = function(uid, accessToken, refreshToken) {
		//JG: Actually save the useful stuff
		winston.verbose("Storing received fb access information for uid(" + uid + ") accessToken(" + accessToken + ") refreshToken(" + refreshToken + ")");
		User.setUserField(uid, 'vkontakteaccesstoken', accessToken);
		User.setUserField(uid, 'vkontakterefreshtoken', refreshToken);
	};

	Vkontakte.login = function(vkontakteID, username, displayName, email, accessToken, refreshToken, picture, callback) {
		//console.log('our email!!!!!!');
		//console.log(email);
		if (!email) {
			email = username + '@users.noreply.vkontakte.com';
		}

			Vkontakte.getUidByvkontakteID = function(vkontakteID, callback) {
			db.getObjectField('vkontakteid:uid', vkontakteID, function(err, uid) {
			if (err) {
				callback(err);
			} else {
				callback(null, uid);
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
			"route": constants.admin.route,
			"icon": constants.admin.icon,
			"name": constants.name
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
