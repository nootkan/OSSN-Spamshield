# OSSN SpamShield

**Version:** 1.0.0  
**Author:** Van Isle Web Solutions  
**License:** GPL-3.0-or-later  
**Compatibility:** OSSN 6.0+

## Description

OSSN SpamShield is an invisible anti-spam and bot protection component for Open Source Social Network. It provides multiple layers of protection against spam registrations and bot attacks while maintaining a seamless experience for legitimate users.

## Features

### Multi-Layer Protection

1. **Honeypot Field** - Hidden field that catches bots that blindly fill all form fields
2. **JavaScript Detection** - Requires JavaScript to be enabled (blocks headless bots)
3. **Cookie Verification** - Requires cookies to be enabled (blocks cookie-less bots)
4. **Timing Check** - Prevents instant form submissions (configurable minimum time)
5. **User Agent Filtering** - Blocks suspicious user agents (curl, wget, python scripts, etc.)
6. **Rate Limiting** - Prevents rapid-fire submissions from the same IP address

### Smart Validation Rules

- **Guest Users:** Full spam protection on registration, contact forms, and password reset
- **Logged-in Users:** Light protection - can use all platform features freely
- **Administrators:** Completely exempt from timing and JavaScript checks

### Key Benefits

- **Invisible Protection** - No CAPTCHAs or user-facing challenges
- **Zero User Friction** - Legitimate users never see spam checks
- **Social Media Friendly** - Logged-in users can post, comment, and interact freely
- **Admin Friendly** - Admins can work without interference
- **Lightweight** - Minimal performance impact
- **Configurable** - Adjust settings via administrator panel

## Installation

### Requirements

- OSSN 6.0 or higher
- PHP 8.0 or higher
- JavaScript enabled in users' browsers
- Cookies enabled in users' browsers

### Installation Steps

1. **Download/Upload the component** to your OSSN installation:
```
   /components/OssnSpamShield/
```

2. **Ensure the following directory structure:**
```
   OssnSpamShield/
├── actions/
│   └── admin/
│       └── settings.php
├── locale/
│   └── ossn.en.php
├── pages/
│   └── administrator/
│       └── ossn_spamshield.php
├── plugins/
│   └── default/
│       ├── css/
│       │   └── ossn_spamshield.php
│       ├── forms/
│       │   ├── OssnSpamShield/
│       │   │   └── administrator/
│       │   │       └── settings.php
│       │   └── signup/
│       │       └── before/
│       │           └── spamshield_fields.php
│       ├── js/
│       │   └── ossn_spamshield.php
│       └── settings/
│           └── administrator/
│               └── OssnSpamShield/
│                   └── settings.php
├── ossn_com.php
├── ossn_com.xml
└── README.md
```

3. **Log in as administrator**

4. **Go to:** Administrator → Configure → Components

5. **Find "OssnSpamShield"** in the component list

6. **Click "Enable"**

7. **Configure settings:** Administrator → Spam Shield

8. **Clear cache** (if needed): Administrator → Cache

9. **Test the installation** (see Testing section below)

## Configuration

### Default Settings

The component comes with sensible defaults:

- **Enabled:** Yes
- **Minimum Submit Time:** 7 seconds
- **Rate Limit Window:** 10 seconds
- **Cookie SameSite Policy:** Lax

### Adjusting Settings

1. Log in as administrator
2. Go to: Administrator → Spam Shield
3. Adjust settings as needed:
   - **Enable/Disable** - Turn protection on or off
   - **Minimum Submit Time** - Time in seconds before form can be submitted (0-60)
   - **Rate Limit Window** - Time window for rate limiting (1-300 seconds)
   - **Cookie SameSite Policy** - Strict, Lax, or None

## How It Works

### For Guest/Anonymous Users (Registration)

When a guest tries to register:

1. **Page Load:** Server injects honeypot (`_psh`) and timestamp (`_pst`) fields
2. **Page Load:** Server sets a probe cookie (`ps_probe`)
3. **User Fills Form:** JavaScript adds the `ps_ajax` flag
4. **User Submits:** All protection layers validate:
   - Honeypot must be empty
   - JavaScript flag must be present
   - Cookies must be enabled
   - Minimum time must have passed
   - User agent must be legitimate
   - Rate limit must not be exceeded

### For Logged-in Users

- Can create content freely (posts, comments, photos)
- Can perform social actions without spam checks
- Still protected by: Honeypot, Cookie check, UA check, Rate limiting

### For Administrators

- Completely exempt from timing and JavaScript checks
- Can perform all actions without spam interference

## Testing Your Installation

### Test 1: Normal Registration (Should PASS)

1. Log out completely
2. Go to registration page
3. Fill out all fields
4. Wait 7 seconds (if using auto fill)
5. Submit the form
6. **Expected:** Registration succeeds

### Test 2: JavaScript Disabled (Should BLOCK)

1. Disable JavaScript in browser
2. Try to register
3. **Expected:** Error about JavaScript being required
4. Re-enable JavaScript

### Test 3: Rapid Submissions (Should BLOCK)

1. Fill out registration form
2. Click submit button twice quickly
3. **Expected:** Second submission blocked with rate limit error

### Test 4: Logged-in User Actions (Should PASS)

1. Log in as regular user
2. Create a post, comment, or upload photo
3. **Expected:** Content created successfully

### Test 5: Admin Actions (Should PASS)

1. Log in as administrator
2. Perform multiple quick actions
3. **Expected:** All actions succeed immediately

## Troubleshooting

### Users Can't Register

**Issue:** Legitimate users are blocked from registering

**Solutions:**
1. Ensure JavaScript is enabled in their browser
2. Ensure cookies are enabled in their browser
3. If using auto fill check that they're waiting at least 7 seconds before submitting (most humans take 10-30 seconds to manually fill out a form)
4. Check error logs for specific error messages
5. Verify component is configured correctly

### Logged-in Users Can't Post Content

**Issue:** Users get spam errors when creating content

**This shouldn't happen with current configuration. If it does:**
1. Verify user is actually logged in
2. Clear browser cache
3. Clear OSSN cache (Administrator → Cache)
4. Check error logs

### Component Activation Fails

**Issue:** Errors when trying to enable component

**Solutions:**
1. Ensure OSSN 6.0 or higher
2. Ensure PHP 8.0 or higher
3. Check file permissions on component directory
4. Check PHP error logs

### JavaScript Not Loading

**Issue:** `ps_ajax` field not being added to forms

**Check:**
1. Clear browser cache
2. Clear OSSN cache (Administrator → Cache)
3. Check browser console (F12) for JavaScript errors
4. Verify file exists: `/plugins/default/js/ossn_spamshield/js.php`

## Database

The component creates one database table:

**Table:** `ossn_spamshield_log`

**Columns:**
- `id` - Auto-increment primary key
- `time_created` - Unix timestamp of event
- `ip` - IP address of the blocked request
- `user_guid` - User GUID if logged in (NULL for guests)
- `type` - Type of check that triggered
- `reason` - Human-readable reason
- `details` - JSON-encoded additional details

**Viewing Logs:**

You can query the logs directly:
```sql
SELECT * FROM ossn_spamshield_log ORDER BY time_created DESC LIMIT 100;
```

A future version may include an admin UI for viewing logs.

## Performance

- **Impact:** Minimal - validation adds <1ms per request
- **Database:** One INSERT per blocked attempt only
- **Memory:** Negligible - ~1KB per request

## Uninstallation

1. **Disable the component** in Administrator → Components
2. **Delete the component folder** from `/components/OssnSpamShield/`
3. **Optional:** Remove the database table:
```sql
   DROP TABLE IF EXISTS ossn_spamshield_log;
```

## Changelog

### Version 1.0.0 (December 2024)
- Initial release
- Multi-layer spam protection
- Smart validation rules for guests, users, and admins
- Logging system
- Admin configuration interface
- OSSN 6.0+ compatibility

## Support

**Developer:** Van Isle Web Solutions

**Issues & Feature Requests:**
Please provide:
- OSSN version
- PHP version
- Component version
- Detailed description
- Error messages from logs

## License

GPL-3.0-or-later

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; version 3 of the License.

---

**Need help?** Check the OSSN community forums at https://www.opensource-socialnetwork.org/
