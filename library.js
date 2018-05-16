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

	Vkontakte.preinit = function(data, callback) {
		// Settings
		meta.settings.get('sso-vkontakte', function(err, settings) {
			Vkontakte.settings = settings;
			callback(null, data);
		});
	};

	Vkontakte.init = function(data, callback) {
		function render(req, res, next) {
			res.render('admin/plugins/sso-vkontakte', {});
		}

		data.router.get('/admin/plugins/sso-vkontakte', data.middleware.admin.buildHeader, render);
		data.router.get('/api/admin/plugins/sso-vkontakte', render);

		callback();
	};

	Vkontakte.getStrategy = function(strategies, callback) {
		meta.settings.get('sso-vkontakte', function(err, settings) {
			if (!err && settings.id && settings.secret) {
				passport.use(new passportVK({
					clientID: settings.id,
					clientSecret: settings.secret,
					callbackURL: nconf.get('url') + '/auth/vkontakte/callback'
				}, function(accessToken, refreshToken, params, profile, done) {
					Vkontakte.login(profile.id, profile.username, profile.displayName, params.email, profile.photos[0].value, function(err, user) {
						var email = params.email;
						if (err) {
							return done(err);
						}
						done(null, user);
					});
				}));

				strategies.push({
					name: 'vkontakte',
					url: '/auth/vkontakte',
					callbackURL: '/auth/vkontakte/callback',
					icon: 'vk fa-vk',
					scope: 'email'
				});
			}

			callback(null, strategies);
		});
	};

	Vkontakte.appendUserHashWhitelist = function (data, callback) {
		data.whitelist.push('vkontakteid');//death remember
		return setImmediate(callback, null, data);
	};

	Vkontakte.storeTokens = function(uid, accessToken, refreshToken) {
		//JG: Actually save the useful stuff
		winston.verbose("Storing received fb access information for uid(" + uid + ") accessToken(" + accessToken + ") refreshToken(" + refreshToken + ")");
		user.setUserField(uid, 'vkontakteaccesstoken', accessToken);
		user.setUserField(uid, 'vkontakterefreshtoken', refreshToken);
	};

	Vkontakte.login = function(vkontakteID, username, displayName, email, picture, callback) {
		//console.log('our email!!!!!!');
		//console.log(email);
		if (!email) {
			email = username + '@users.noreply.vkontakte.com';
		}

		Vkontakte.getUidByvkontakteID(vkontakteID, function(err, uid) {
			if (err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid
				});
			} else {
				// New User
				var success = function(uid) {
					// Save vkontakte-specific information to the user
					User.setUserField(uid, 'vkontakteid', vkontakteID);
					db.setObjectField('vkontakteid:uid', vkontakteID, uid);
					var autoConfirm = Vkontakte.settings && Vkontakte.settings.autoconfirm === "on" ? 1: 0;
					User.setUserField(uid, 'email:confirmed', autoConfirm);

					if (autoConfirm) {
						db.sortedSetRemove('users:notvalidated', uid);
					}

					// Save their photo, if present
					if (picture) {
						User.setUserField(uid, 'uploadedpicture', picture);
						User.setUserField(uid, 'picture', picture);
					}

					callback(null, {
						uid: uid
					});
				};

				User.getUidByEmail(email, function(err, uid) {
					if(err) {
						return callback(err);
					}

					if (!uid) {
						User.create({username: displayName, email: email}, function(err, uid) {
							if(err) {
								return callback(err);
							}

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	Vkontakte.getUidByvkontakteID = function(vkontakteID, callback) {
		db.getObjectField('vkontakteid:uid', vkontakteID, function(err, uid) {
			if (err) {
				callback(err);
			} else {
				callback(null, uid);
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
			}
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
