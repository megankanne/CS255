// ==UserScript==
// @namespace      CS255-Tran-Kanne
// @name           CS255-Tran-Kanne
// @description    CS255-Tran-Kanne - CS255 Assignment 1
// @version        1.5
//
// 
// @include        http://www.facebook.com/*
// @include        https://www.facebook.com/*
// @exclude        http://www.facebook.com/messages/*
// @exclude        https://www.facebook.com/messages/*
// @exclude        http://www.facebook.com/events/*
// @exclude        https://www.facebook.com/events/*
// ==/UserScript==

/*
  Step 1: change @namespace, @name, and @description above.
  Step 2: Change the filename to the format "CS255-Lastname1-Lastname2.user.js"
  Step 3: Install this file as an (unpacked) Chrome extension using manifest.json.
  Step 4: Fill in the functions below.
  */

// Strict mode makes it easier to catch errors.
// You may comment this out if you want.
// See http://ejohn.org/blog/ecmascript-5-strict-mode-json-and-more/
"use strict";

var my_username; // user signed in as
var keys = {}; // association map of keys: group -> key

// Some initialization functions are called at the very end of this script.
// You only have to edit the top portion.

// Return the encryption of the message for the given group, in the form of a string.
//
// @param {String} plainText String to encrypt.
// @param {String} group Group name.
// @return {String} Encryption of the plaintext, encoded as a string.
function Encrypt(plainText, group) {
  // CS255-todo: encrypt the plainText, using key for the group.
  if ((plainText.indexOf('aes:') == 0) || (plainText.length < 1)) {
    alert("Try entering a message (the button works only once)");
    return plainText;
  } else {
    // encrypt, add tag.
    var key = sjcl.codec.base64.toBits(keys[group]);
    var ctext = encrypttext(plainText, key);
    return 'aes:' + ctext;
  }

}

// Return the decryption of the message for the given group, in the form of a string.
// Throws an error in case the string is not properly encrypted.
//
// @param {String} cipherText String to decrypt.
// @param {String} group Group name.
// @return {String} Decryption of the ciphertext.
function Decrypt(cipherText, group) {
  if (cipherText.indexOf('aes:') == 0) {
    // decrypt, ignore the tag.
    var key = sjcl.codec.base64.toBits(keys[group]);
    var decrypt_text = decrypttext(cipherText.substring(4), key);
    return decrypt_text;
  } else {
    throw "not encrypted";
  }
}

function encrypttext (text, key) {
  /* Random IV is random */
  var xortext = GetRandomValues(4); 
  var ctext = xortext;
  var cipher = new sjcl.cipher.aes(key);
  var textblock = sjcl.codec.utf8String.toBits(text);
  var bitLength = sjcl.bitArray.bitLength(textblock);

  /* If the length is a multiple of block length */
  var extra_bytes = (128 - bitLength % 128) / 8;
  /* Padding */
  for (var i = 0; i < extra_bytes; i++) {
    text = text + String.fromCharCode(extra_bytes);
  }
  /* Convert to bit array */
  textblock = sjcl.codec.utf8String.toBits(text);

  for (var i = 0; i <= textblock.length-4; i = i + 4) {
    /* Current block */
    var curblock = sjcl.bitArray.bitSlice(textblock, i*32, (i+4)*32);
    /* Xor the two blocks together */
    var xor_result = sjcl.bitArray._xor4(curblock, xortext);
    /* Encrypted the xor result */
    xortext = cipher.encrypt(xor_result);
    
    /* Concatenate the next block */
    ctext = sjcl.bitArray.concat(ctext,xortext);
  } 
  /* Return base64 string */
  return sjcl.codec.base64.fromBits(ctext);
}

function decrypttext (text, key) {
  /* Random key is 16 bit */
  var xortext = 0; 
  var dtext = Array();
  var cipher = new sjcl.cipher.aes(key);
  var textblock = sjcl.codec.base64.toBits(text);

  for (var i = 4; i <= textblock.length-4; i = i + 4) {
    /* Current block */
    var curblock = cipher.decrypt(sjcl.bitArray.bitSlice(textblock, i*32, (i+4)*32));
    /* The next encrypted block */
    xortext = sjcl.bitArray.bitSlice(textblock, (i-4)*32, i*32);
    /* De-xor the block */
    var xor_result = sjcl.bitArray._xor4(curblock, xortext);
    /* Concatenate the next block */
    dtext = sjcl.bitArray.concat(dtext, xor_result);
  } 
  /* Convert to utf8 and remove the padding */
  dtext = sjcl.codec.utf8String.fromBits(dtext);
  var extra_bytes = dtext.charCodeAt(dtext.length-1);
  dtext = dtext.substring(0, dtext.length-extra_bytes);
  return dtext;
}

// Generate a new key for the given group.
//
// @param {String} group Group name.
function GenerateKey(group) {
  var salt = cs255.localStorage.getItem('facebook-salt-' + my_username);
  /* The password to generate group key is the group name */
  var key = sjcl.misc.pbkdf2(group, salt, null, 128, null);
  keys[group] = sjcl.codec.base64.fromBits(key);
  SaveKeys();
}

// Take the current group keys, and save them to disk.
function SaveKeys() {
  var password_stored = sjcl.codec.base64.toBits(sessionStorage.getItem('current-key-' + my_username));
  /* Encrypt the keys and store them */
  var key_str = encrypttext(JSON.stringify(keys),password_stored);

  cs255.localStorage.setItem('facebook-keys-' + my_username, key_str);
}

// Load the group keys from disk.
function LoadKeys() {
  var password_stored = sessionStorage.getItem('current-key-' + my_username);
 
  /* If the session is already exists don't ask the user again */
  if (!password_stored) {
    keys = {}; // Reset the keys.
    var saved = cs255.localStorage.getItem('facebook-keys-' + my_username);
    if (saved) { 
      /* Prompt the user to enter the key database password */
      var password = prompt("Please enter your key database password","");

      /* Get the salt of the password */
      var salt = cs255.localStorage.getItem('facebook-salt-' + my_username);

      /* Generate the key from the password given by the user */
      var generated_key = sjcl.misc.pbkdf2(password, salt, null, 128, null);
      var decrypted_keys = JSON.parse(decrypttext(saved,generated_key));

      if ("test_string" in decrypted_keys && decrypted_keys["test_string"] == "correct_password") {
        alert("Correct password:");
        /* Descrypt the keys and parse them */
        keys = decrypted_keys;
        sessionStorage.setItem('current-key-' + my_username, sjcl.codec.base64.fromBits(generated_key));
        
      } else {
        alert("Wrong password:");
      }
    } else {
      /* If the key database hasnt existed, ask the user to create a new password */
      var password = prompt("Please create your key database password","");

      /* Generate salt */
      var salt = sjcl.codec.base64.fromBits(GetRandomValues(4));
      cs255.localStorage.setItem('facebook-salt-' + my_username, salt);

      /* To do store the key as a secure hash */
      var key = sjcl.misc.pbkdf2(password, salt, null, 128, null);
       
      /* Initialize the database */
      var json = encrypttext('{"test_string":"correct_password"}', key);
      
      cs255.localStorage.setItem('facebook-keys-' + my_username, json);

      json = decrypttext(json,key)    
      keys = JSON.parse(json);
      
      sessionStorage.setItem('current-key-' + my_username, sjcl.codec.base64.fromBits(key));
    }
  } else {
    alert("Session storage exists");
    keys = JSON.parse(decrypttext(cs255.localStorage.getItem('facebook-keys-' + my_username),sjcl.codec.base64.toBits(password_stored)));
    
  } 
}

/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
//
// Using the AES primitives from SJCL for this assignment.
//
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////

/*
  Here are the basic cryptographic functions (implemented farther down)
  you need to do the assignment:

  function sjcl.cipher.aes(key)

  This function creates a new AES encryptor/decryptor with a given key.
  Note that the key must be an array of 4, 6, or 8 32-bit words for the
  function to work.  For those of you keeping score, this constructor does
  all the scheduling needed for the cipher to work. 

  encrypt: function(plaintext)

  This function encrypts the given plaintext.  The plaintext argument
  should take the form of an array of four (32-bit) integers, so the plaintext
  should only be one block of data.

  decrypt: function(ciphertext)

  This function decrypts the given ciphertext.  Again, the ciphertext argument
  should be an array of 4 integers.

  A silly example of this in action:

    var key1 = new Array(8);
    var cipher = new sjcl.cipher.aes(key1);
    var dumbtext = new Array(4);
    dumbtext[0] = 1; dumbtext[1] = 2; dumbtext[2] = 3; dumbtext[3] = 4;
    var ctext = cipher.encrypt(dumbtext);
    var outtext = cipher.decrypt(ctext);

  Obviously our key is just all zeroes in this case, but this should illustrate
  the point.
  */

/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
//
// Should not _have_ to change anything below here.
// Helper functions and sample code.
//
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////

var cs255 = {
  localStorage: {
    setItem: function(key, value) {
      localStorage.setItem(key, value);
      var newEntries = {};
      newEntries[key] = value;
      chrome.storage.local.set(newEntries);
    },
    getItem: function(key) {
      return localStorage.getItem(key);
    },
    clear: function() {
      chrome.storage.local.clear();
    }
  }
}

if (typeof chrome.storage === "undefined") {
  var id = function() {};
  chrome.storage = {local: {get: id, set: id}};
}
else {
  // See if there are any values stored with the extension.
  chrome.storage.local.get(null, function(onDisk) {
    for (key in onDisk) {
      localStorage.setItem(key, onDisk[key]);
    }
  });
}

// Get n 32-bit-integers entropy as an array. Defaults to 1 word
function GetRandomValues(n) {

  var entropy = new Int32Array(n);
  // This should work in WebKit.
  window.crypto.getRandomValues(entropy);

  // Typed arrays can be funky,
  // so let's convert it to a regular array for our purposes.
  var regularArray = [];
  for (var i = 0; i < entropy.length; i++) {
    regularArray.push(entropy[i]);
  }
  return regularArray;
}

// From http://aymanh.com/9-javascript-tips-you-may-not-know#Assertion
// Just in case you want an assert() function

function AssertException(message) {
  this.message = message;
}
AssertException.prototype.toString = function() {
  return 'AssertException: ' + this.message;
}

function assert(exp, message) {
  if (!exp) {
    throw new AssertException(message);
  }
}

// Very primitive encryption.
function rot13(text) {
  // JS rot13 from http://jsfromhell.com/string/rot13
  return text.replace(/[a-zA-Z]/g,

    function(c) {
      return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
    });
}

function SetupUsernames() {
  // get who you are logged in as
  var meta = document.getElementsByClassName('navItem tinyman')[0];

  // If we can't get a username, halt execution.
  assert (typeof meta !== "undefined", "CS255 script failed. No username detected. (This is usually harmless.)");
  
  var usernameMatched = /www.facebook.com\/(.*?)ref=tn_tnmn/i.exec(meta.innerHTML);
  usernameMatched = usernameMatched[1].replace(/&amp;/, '');
  usernameMatched = usernameMatched.replace(/\?/, '');
  usernameMatched = usernameMatched.replace(/profile\.phpid=/, '');
  my_username = usernameMatched; // Update global.
}

function getClassName(obj) {
  if (typeof obj != "object" || obj === null) return false;
  return /(\w+)\(/.exec(obj.constructor.toString())[1];
}

function hasClass(element, cls) {
  var r = new RegExp('\\b' + cls + '\\b');
  return r.test(element.className);
}

function DocChanged(e) {
  if (document.URL.match(/groups/)) {
    //Check for adding encrypt button for comments
    if (e.target.nodeType != 3) {
      decryptTextOfChildNodes(e.target);
      decryptTextOfChildNodes2(e.target);
      if (!hasClass(e.target, "crypto")) {
        addEncryptCommentButton(e.target);
      } else {
        return;
      }
    }

    tryAddEncryptButton();
  }
  //Check for adding keys-table
  if (document.URL.match('settings')) {
    if (!document.getElementById('cs255-keys-table') && !hasClass(e.target, "crypto")) {
      AddEncryptionTab();
      UpdateKeysTable();
    }
  }
}
//Decryption of posts


function decryptTextOfChildNodes(e) {
  var msgs = e.getElementsByClassName('messageBody');

  if (msgs.length > 0) {
    var msgs_array = new Array();
    for (var i = 0; i < msgs.length; ++i) {
      msgs_array[i] = msgs[i];
    }
    for (var i = 0; i < msgs_array.length; ++i) {
      DecryptMsg(msgs_array[i]);
    }
  }

}
//Decryption of comments


function decryptTextOfChildNodes2(e) {
  var msgs = e.getElementsByClassName('UFICommentBody');

  if (msgs.length > 0) {
    var msgs_array = new Array();
    for (var i = 0; i < msgs.length; ++i) {
      msgs_array[i] = msgs[i];
    }
    for (var i = 0; i < msgs_array.length; ++i) {
      DecryptMsg(msgs_array[i]);
    }
  }

}

function RegisterChangeEvents() {
  // Facebook loads posts dynamically using AJAX, so we monitor changes
  // to the HTML to discover new posts or comments.
  var doc = document.addEventListener("DOMNodeInserted", DocChanged, false);
}

function AddEncryptionTab() {

  // On the Account Settings page, show the key setups
  if (document.URL.match('settings')) {
    var div = document.getElementById('contentArea');
    if (div) {
      var h2 = document.createElement('h2');
      h2.setAttribute("class", "crypto");
      h2.innerHTML = "CS255 Keys";
      div.appendChild(h2);

      var table = document.createElement('table');
      table.id = 'cs255-keys-table';
      table.style.borderCollapse = "collapse";
      table.setAttribute("class", "crypto");
      table.setAttribute('cellpadding', 3);
      table.setAttribute('cellspacing', 1);
      table.setAttribute('border', 1);
      table.setAttribute('width', "80%");
      div.appendChild(table);
    }
  }
}

//Encrypt button is added in the upper left corner


function tryAddEncryptButton(update) {

  // Check if it already exists.
  if (document.getElementById('encrypt-button')) {
    return;
  }

  var encryptWrapper = document.createElement("span");
  encryptWrapper.style.float = "right";


  var encryptLabel = document.createElement("label");
  encryptLabel.setAttribute("class", "submitBtn uiButton uiButtonConfirm");

  var encryptButton = document.createElement("input");
  encryptButton.setAttribute("value", "Encrypt");
  encryptButton.setAttribute("type", "button");
  encryptButton.setAttribute("id", "encrypt-button");
  encryptButton.setAttribute("class", "encrypt-button");
  encryptButton.addEventListener("click", DoEncrypt, false);

  encryptLabel.appendChild(encryptButton);
  encryptWrapper.appendChild(encryptLabel);

  var liParent;
  try {
    liParent = document.getElementsByName("xhpc_message")[0].parentNode;
  } catch(e) {
    return;
  }
  liParent.appendChild(encryptWrapper);

  decryptTextOfChildNodes(document);
  decryptTextOfChildNodes2(document);

}

function addEncryptCommentButton(e) {

  var commentAreas = e.getElementsByClassName('textInput UFIAddCommentInput');

  for (var j = 0; j < commentAreas.length; j++) {

    if (commentAreas[j].parentNode.parentNode.parentNode.parentNode.getElementsByClassName("encrypt-comment-button").length > 0) {
      continue;
    }

    var encryptWrapper = document.createElement("span");
    encryptWrapper.setAttribute("class", "");
    encryptWrapper.style.cssFloat = "right";
    encryptWrapper.style.cssPadding = "2px";


    var encryptLabel = document.createElement("label");
    encryptLabel.setAttribute("class", "submitBtn uiButton uiButtonConfirm crypto");

    var encryptButton = document.createElement("input");
    encryptButton.setAttribute("value", "Encrypt");
    encryptButton.setAttribute("type", "button");
    encryptButton.setAttribute("class", "encrypt-comment-button crypto");
    encryptButton.addEventListener("click", DoEncrypt, false);

    encryptLabel.appendChild(encryptButton);
    encryptWrapper.appendChild(encryptLabel);

    commentAreas[j].parentNode.parentNode.parentNode.parentNode.appendChild(encryptWrapper);
  }
}

function AddElements() {
  if (document.URL.match(/groups/)) {
    tryAddEncryptButton();
    addEncryptCommentButton(document);
  }
  AddEncryptionTab()
}

function GenerateKeyWrapper() {
  var group = document.getElementById('gen-key-group').value;

  if (group.length < 1) {
    alert("You need to set a group");
    return;
  }

  GenerateKey(group);
  
  UpdateKeysTable();
}

function UpdateKeysTable() {
  var table = document.getElementById('cs255-keys-table');
  if (!table) return;
  table.innerHTML = '';

  // ugly due to events + GreaseMonkey.
  // header
  var row = document.createElement('tr');
  var th = document.createElement('th');
  th.innerHTML = "Group";
  row.appendChild(th);
  th = document.createElement('th');
  th.innerHTML = "Key";
  row.appendChild(th);
  th = document.createElement('th');
  th.innerHTML = "&nbsp;";
  row.appendChild(th);
  table.appendChild(row);

  // keys
  for (var group in keys) {
    var row = document.createElement('tr');
    row.setAttribute("data-group", group);
    var td = document.createElement('td');
    td.innerHTML = group;
    row.appendChild(td);
    td = document.createElement('td');
    td.innerHTML = keys[group];
    row.appendChild(td);
    td = document.createElement('td');

    var button = document.createElement('input');
    button.type = 'button';
    button.value = 'Delete';
    button.addEventListener("click", function(event) {
      DeleteKey(event.target.parentNode.parentNode);
    }, false);
    td.appendChild(button);
    row.appendChild(td);

    table.appendChild(row);
  }

  // add friend line
  row = document.createElement('tr');

  var td = document.createElement('td');
  td.innerHTML = '<input id="new-key-group" type="text" size="8">';
  row.appendChild(td);

  td = document.createElement('td');
  td.innerHTML = '<input id="new-key-key" type="text" size="24">';
  row.appendChild(td);

  td = document.createElement('td');
  button = document.createElement('input');
  button.type = 'button';
  button.value = 'Add Key';
  button.addEventListener("click", AddKey, false);
  td.appendChild(button);
  row.appendChild(td);

  table.appendChild(row);

  // generate line
  row = document.createElement('tr');

  td = document.createElement('td');
  td.innerHTML = '<input id="gen-key-group" type="text" size="8">';
  row.appendChild(td);

  table.appendChild(row);

  td = document.createElement('td');
  td.colSpan = "2";
  button = document.createElement('input');
  button.type = 'button';
  button.value = 'Generate New Key';
  button.addEventListener("click", GenerateKeyWrapper, false);
  td.appendChild(button);
  row.appendChild(td);
}

function AddKey() {
  var g = document.getElementById('new-key-group').value;
  if (g.length < 1) {
    alert("You need to set a group");
    return;
  }
  var k = document.getElementById('new-key-key').value;
  keys[g] = k;
  SaveKeys();
  UpdateKeysTable();
}

function DeleteKey(e) {
  var group = e.getAttribute("data-group");
  delete keys[group];
  SaveKeys();
  UpdateKeysTable();
}

function DoEncrypt(e) {
  // triggered by the encrypt button
  // Contents of post or comment are saved to dummy node. So updation of contens of dummy node is also required after encryption
  if (e.target.className == "encrypt-button") {
    var textHolder = document.getElementsByClassName("uiTextareaAutogrow input mentionsTextarea textInput")[0];
    var dummy = document.getElementsByName("xhpc_message")[0];
  } else {
    console.log(e.target);
    var dummy = e.target.parentNode.parentNode.parentNode.parentNode.parentNode.parentNode.getElementsByClassName("mentionsHidden")[0];
    var textHolder = e.target.parentNode.parentNode.parentNode.parentNode.getElementsByClassName("textInput mentionsTextarea")[0];
  }

  //Get the plain text
  //var vntext=textHolder.value;
  var vntext = dummy.value;

  //Ecrypt
  var vn2text = Encrypt(vntext, CurrentGroup());

  //Replace with encrypted text
  textHolder.value = vn2text;
  dummy.value = vn2text;

  textHolder.select();

}

// Currently results in a TypeError if we're not on a group page.
function CurrentGroup() {
  // Try a few DOM elements that might exist, and would contain the group name.
  var domElement = document.getElementById('groupsJumpTitle') || document.getElementById('groupsSkyNavTitleTab');
  var groupName = domElement.innerText;
  return groupName;
}

function GetMsgText(msg) {
  return msg.innerHTML;
}

function getTextFromChildren(parent, skipClass, results) {
  var children = parent.childNodes,
  item;
  var re = new RegExp("\\b" + skipClass + "\\b");
  for (var i = 0, len = children.length; i < len; i++) {
    item = children[i];
    // if text node, collect it's text
    if (item.nodeType == 3) {
      results.push(item.nodeValue);
    } else if (!item.className || !item.className.match(re)) {
      // if it has a className and it doesn't match 
      // what we're skipping, then recurse on it
      getTextFromChildren(item, skipClass, results);
    }
  }
}

function GetMsgTextForDecryption(msg) {
  try {
    var visibleDiv = msg.getElementsByClassName("text_exposed_root");
    if (visibleDiv.length) {
      var visibleDiv = document.getElementsByClassName("text_exposed_root");
      var text = [];
      getTextFromChildren(visibleDiv[0], "text_exposed_hide", text);
      var mg = text.join("");
      return mg;

    } else {
      var innerText = msg.innerText;

      // Get rid of the trailing newline, if there is one.
      if (innerText[innerText.length-1] === '\n') {
        innerText = innerText.slice(0, innerText.length-1);
      }

      return innerText;
    }

  } catch(err) {
    return msg.innerText;
  }
}

function wbr(str, num) {
  //return str.replace(RegExp("(\\w{" + num + "})(\\w)", "g"), function(all,text,char){ 
  //  return text + "<wbr>" + char; 
  //}); 
return str.replace(RegExp("(.{" + num + "})(.)", "g"), function(all, text, char) {
  return text + "<wbr>" + char;
});
}

function SetMsgText(msg, new_text) {
  //msg.innerHTML = wbr(new_text, 50);
  msg.innerHTML = new_text;
}

// Rudimentary attack against HTML/JAvascript injection. From mustache.js. https://github.com/janl/mustache.js/blob/master/mustache.js#L53
function escapeHtml(string) {

  var entityMap = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': '&quot;',
    "'": '&#39;',
    "/": '&#x2F;'
  };

  return String(string).replace(/[&<>"'\/]/g, function (s) {
    return entityMap[s];
  });
}

function DecryptMsg(msg) {
  // we mark the box with the class "decrypted" to prevent attempting to decrypt it multiple times.
  if (!/decrypted/.test(msg.className)) {
    var txt = GetMsgTextForDecryption(msg);

    var displayHTML;
    try {
      var group = CurrentGroup();
      var decryptedMsg = Decrypt(txt, group);
      decryptedMsg = escapeHtml(decryptedMsg);
      displayHTML = '<font color="#00AA00">Decrypted message: ' + decryptedMsg + '</font><br><hr>' + txt;
    }
    catch (e) {
      displayHTML = '<font color="#FF88">Could not decrypt (' + e + ').</font><br><hr>' + txt;
    }

    SetMsgText(msg, displayHTML);
    msg.className += " decrypted";
  }
}


/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
//
// Below here is from other libraries. Here be dragons.
//
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////


/** @fileOverview Javascript cryptography implementation.
 *
 * Crush to remove comments, shorten variable names and
 * generally reduce transmission size.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

 "use strict"; /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
 /*global document, window, escape, unescape */

 /** @namespace The Stanford Javascript Crypto Library, top-level namespace. */
 var sjcl = { /** @namespace Symmetric ciphers. */
  cipher: {},

  /** @namespace Hash functions.  Right now only SHA256 is implemented. */
  hash: {},

  /** @namespace Block cipher modes of operation. */
  mode: {},

  /** @namespace Miscellaneous.  HMAC and PBKDF2. */
  misc: {},

  /**
   * @namespace Bit array encoders and decoders.
   *
   * @description
   * The members of this namespace are functions which translate between
   * SJCL's bitArrays and other objects (usually strings).  Because it
   * isn't always clear which direction is encoding and which is decoding,
   * the method names are "fromBits" and "toBits".
   */
   codec: {},

   /** @namespace Exceptions. */
   exception: { /** @class Ciphertext is corrupt. */
    corrupt: function(message) {
      this.toString = function() {
        return "CORRUPT: " + this.message;
      };
      this.message = message;
    },

    /** @class Invalid parameter. */
    invalid: function(message) {
      this.toString = function() {
        return "INVALID: " + this.message;
      };
      this.message = message;
    },

    /** @class Bug or missing feature in SJCL. */
    bug: function(message) {
      this.toString = function() {
        return "BUG: " + this.message;
      };
      this.message = message;
    },

    // Added by mbarrien to fix an SJCL bug.
    /** @class Not ready to encrypt. */
    notready: function(message) {
      this.toString = function() {
        return "NOTREADY: " + this.message;
      };
      this.message = message;
    }
  }
};

/** @fileOverview Low-level AES implementation.
 *
 * This file contains a low-level implementation of AES, optimized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-domain implementation by Vincent
 * Rijmen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4, 6 or 8 words.
 *
 * @class Advanced Encryption Standard (low-level interface)
 */
 sjcl.cipher.aes = function(key) {
  if (!this._tables[0][0][0]) {
    this._precompute();
  }

  var i, j, tmp, encKey, decKey, sbox = this._tables[0][4],
  decTable = this._tables[1],
  keyLen = key.length,
  rcon = 1;

  if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
    throw new sjcl.exception.invalid("invalid aes key size");
  }

  this._key = [encKey = key.slice(0), decKey = []];

  // schedule encryption keys
  for (i = keyLen; i < 4 * keyLen + 28; i++) {
    tmp = encKey[i - 1];

    // apply sbox
    if (i % keyLen === 0 || (keyLen === 8 && i % keyLen === 4)) {
      tmp = sbox[tmp >>> 24] << 24 ^ sbox[tmp >> 16 & 255] << 16 ^ sbox[tmp >> 8 & 255] << 8 ^ sbox[tmp & 255];

      // shift rows and add rcon
      if (i % keyLen === 0) {
        tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24;
        rcon = rcon << 1 ^ (rcon >> 7) * 283;
      }
    }

    encKey[i] = encKey[i - keyLen] ^ tmp;
  }

  // schedule decryption keys
  for (j = 0; i; j++, i--) {
    tmp = encKey[j & 3 ? i : i - 4];
    if (i <= 4 || j < 4) {
      decKey[j] = tmp;
    } else {
      decKey[j] = decTable[0][sbox[tmp >>> 24]] ^ decTable[1][sbox[tmp >> 16 & 255]] ^ decTable[2][sbox[tmp >> 8 & 255]] ^ decTable[3][sbox[tmp & 255]];
    }
  }
};

sjcl.cipher.aes.prototype = {
  // public
  /* Something like this might appear here eventually
  name: "AES",
  blockSize: 4,
  keySizes: [4,6,8],
  */

  /**
   * Encrypt an array of 4 big-endian words.
   * @param {Array} data The plaintext.
   * @return {Array} The ciphertext.
   */
   encrypt: function(data) {
    return this._crypt(data, 0);
  },

  /**
   * Decrypt an array of 4 big-endian words.
   * @param {Array} data The ciphertext.
   * @return {Array} The plaintext.
   */
   decrypt: function(data) {
    return this._crypt(data, 1);
  },

  /**
   * The expanded S-box and inverse S-box tables.  These will be computed
   * on the client so that we don't have to send them down the wire.
   *
   * There are two tables, _tables[0] is for encryption and
   * _tables[1] is for decryption.
   *
   * The first 4 sub-tables are the expanded S-box with MixColumns.  The
   * last (_tables[01][4]) is the S-box itself.
   *
   * @private
   */
   _tables: [
   [
   [],
   [],
   [],
   [],
   []
   ],
   [
   [],
   [],
   [],
   [],
   []
   ]
   ],

  /**
   * Expand the S-box tables.
   *
   * @private
   */
   _precompute: function() {
    var encTable = this._tables[0],
    decTable = this._tables[1],
    sbox = encTable[4],
    sboxInv = decTable[4],
    i, x, xInv, d = [],
    th = [],
    x2, x4, x8, s, tEnc, tDec;

    // Compute double and third tables
    for (i = 0; i < 256; i++) {
      th[(d[i] = i << 1 ^ (i >> 7) * 283) ^ i] = i;
    }

    for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
      // Compute sbox
      s = xInv ^ xInv << 1 ^ xInv << 2 ^ xInv << 3 ^ xInv << 4;
      s = s >> 8 ^ s & 255 ^ 99;
      sbox[x] = s;
      sboxInv[s] = x;

      // Compute MixColumns
      x8 = d[x4 = d[x2 = d[x]]];
      tDec = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
      tEnc = d[s] * 0x101 ^ s * 0x1010100;

      for (i = 0; i < 4; i++) {
        encTable[i][x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
        decTable[i][s] = tDec = tDec << 24 ^ tDec >>> 8;
      }
    }

    // Compactify.  Considerable speedup on Firefox.
    for (i = 0; i < 5; i++) {
      encTable[i] = encTable[i].slice(0);
      decTable[i] = decTable[i].slice(0);
    }
  },

  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param dir The direction, 0 for encrypt and 1 for decrypt.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
   _crypt: function(input, dir) {
    if (input.length !== 4) {
      throw new sjcl.exception.invalid("invalid aes block size");
    }

    var key = this._key[dir],
      // state variables a,b,c,d are loaded with pre-whitened data
      a = input[0] ^ key[0],
      b = input[dir ? 3 : 1] ^ key[1],
      c = input[2] ^ key[2],
      d = input[dir ? 1 : 3] ^ key[3],
      a2, b2, c2,

      nInnerRounds = key.length / 4 - 2,
      i, kIndex = 4,
      out = [0, 0, 0, 0],
      table = this._tables[dir],

      // load up the tables
      t0 = table[0],
      t1 = table[1],
      t2 = table[2],
      t3 = table[3],
      sbox = table[4];

    // Inner rounds.  Cribbed from OpenSSL.
    for (i = 0; i < nInnerRounds; i++) {
      a2 = t0[a >>> 24] ^ t1[b >> 16 & 255] ^ t2[c >> 8 & 255] ^ t3[d & 255] ^ key[kIndex];
      b2 = t0[b >>> 24] ^ t1[c >> 16 & 255] ^ t2[d >> 8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
      c2 = t0[c >>> 24] ^ t1[d >> 16 & 255] ^ t2[a >> 8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
      d = t0[d >>> 24] ^ t1[a >> 16 & 255] ^ t2[b >> 8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
      kIndex += 4;
      a = a2;
      b = b2;
      c = c2;
    }

    // Last round.
    for (i = 0; i < 4; i++) {
      out[dir ? 3 & -i : i] = sbox[a >>> 24] << 24 ^ sbox[b >> 16 & 255] << 16 ^ sbox[c >> 8 & 255] << 8 ^ sbox[d & 255] ^ key[kIndex++];
      a2 = a;
      a = b;
      b = c;
      c = d;
      d = a2;
    }
    return out;
  }
};

/** @fileOverview Arrays of bits, encoded as arrays of Numbers.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Arrays of bits, encoded as arrays of Numbers.
 *
 * @description
 * <p>
 * These objects are the currency accepted by SJCL's crypto functions.
 * </p>
 *
 * <p>
 * Most of our crypto primitives operate on arrays of 4-byte words internally,
 * but many of them can take arguments that are not a multiple of 4 bytes.
 * This library encodes arrays of bits (whose size need not be a multiple of 8
 * bits) as arrays of 32-bit words.  The bits are packed, big-endian, into an
 * array of words, 32 bits at a time.  Since the words are double-precision
 * floating point numbers, they fit some extra data.  We use this (in a private,
 * possibly-changing manner) to encode the number of bits actually  present
 * in the last word of the array.
 * </p>
 *
 * <p>
 * Because bitwise ops clear this out-of-band data, these arrays can be passed
 * to ciphers like AES which want arrays of words.
 * </p>
 */
 sjcl.bitArray = {
  /**
   * Array slices in units of bits.
   * @param {bitArray a} The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
   * slice until the end of the array.
   * @return {bitArray} The requested slice.
   */
   bitSlice: function(a, bstart, bend) {
    a = sjcl.bitArray._shiftRight(a.slice(bstart / 32), 32 - (bstart & 31)).slice(1);

    return(bend === undefined) ? a : sjcl.bitArray.clamp(a, bend - bstart);
  },

  /**
   * Concatenate two bit arrays.
   * @param {bitArray} a1 The first array.
   * @param {bitArray} a2 The second array.
   * @return {bitArray} The concatenation of a1 and a2.
   */
   concat: function(a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2);
    }

    var out, i, last = a1[a1.length - 1],
    shift = sjcl.bitArray.getPartial(last);
    if (shift === 32) {
      return a1.concat(a2);
    } else {
      return sjcl.bitArray._shiftRight(a2, shift, last | 0, a1.slice(0, a1.length - 1));
    }
  },

  /**
   * Find the length of an array of bits.
   * @param {bitArray} a The array.
   * @return {Number} The length of a, in bits.
   */
   bitLength: function(a) {
    var l = a.length,
    x;
    if (l === 0) {
      return 0;
    }
    x = a[l - 1];
    return(l - 1) * 32 + sjcl.bitArray.getPartial(x);
  },

  /**
   * Truncate an array.
   * @param {bitArray} a The array.
   * @param {Number} len The length to truncate to, in bits.
   * @return {bitArray} A new array, truncated to len bits.
   */
   clamp: function(a, len) {
    if (a.length * 32 < len) {
      return a;
    }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
      a[l - 1] = sjcl.bitArray.partial(len, a[l - 1] & 0x80000000 >> (len - 1), 1);
    }
    return a;
  },

  /**
   * Make a partial word for a bit array.
   * @param {Number} len The number of bits in the word.
   * @param {Number} x The bits.
   * @param {Number} [0] _end Pass 1 if x has already been shifted to the high side.
   * @return {Number} The partial word.
   */
   partial: function(len, x, _end) {
    if (len === 32) {
      return x;
    }
    return(_end ? x | 0 : x << (32 - len)) + len * 0x10000000000;
  },

  /**
   * Get the number of bits used by a partial word.
   * @param {Number} x The partial word.
   * @return {Number} The number of bits used by the partial word.
   */
   getPartial: function(x) {
    return Math.round(x / 0x10000000000) || 32;
  },

  /**
   * Compare two arrays for equality in a predictable amount of time.
   * @param {bitArray} a The first array.
   * @param {bitArray} b The second array.
   * @return {boolean} true if a == b; false otherwise.
   */
   equal: function(a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
      return false;
    }
    var x = 0,
    i;
    for (i = 0; i < a.length; i++) {
      x |= a[i] ^ b[i];
    }
    return(x === 0);
  },

  /** Shift an array right.
   * @param {bitArray} a The array to shift.
   * @param {Number} shift The number of bits to shift.
   * @param {Number} [carry=0] A byte to carry in
   * @param {bitArray} [out=[]] An array to prepend to the output.
   * @private
   */
   _shiftRight: function(a, shift, carry, out) {
    var i, last2 = 0,
    shift2;
    if (out === undefined) {
      out = [];
    }

    for (; shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }
    if (shift === 0) {
      return out.concat(a);
    }

    for (i = 0; i < a.length; i++) {
      out.push(carry | a[i] >>> shift);
      carry = a[i] << (32 - shift);
    }
    last2 = a.length ? a[a.length - 1] : 0;
    shift2 = sjcl.bitArray.getPartial(last2);
    out.push(sjcl.bitArray.partial(shift + shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(), 1));
    return out;
  },

  /** xor a block of 4 words together.
   * @private
   */
   _xor4: function(x, y) {
    return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]];
  }
};

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

 /** @namespace Base64 encoding/decoding */
 sjcl.codec.base64 = {
  /** The base64 alphabet.
   * @private
   */
   _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",

   /** Convert from a bitArray to a base64 string. */
   fromBits: function (arr, _noEquals, _url) {
    var out = "", i, bits=0, c = sjcl.codec.base64._chars, ta=0, bl = sjcl.bitArray.bitLength(arr);
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; out.length * 6 < bl; ) {
      out += c.charAt((ta ^ arr[i]>>>bits) >>> 26);
      if (bits < 6) {
        ta = arr[i] << (6-bits);
        bits += 26;
        i++;
      } else {
        ta <<= 6;
        bits -= 6;
      }
    }
    while ((out.length & 3) && !_noEquals) { out += "="; }
    return out;
  },
  
  /** Convert from a base64 string to a bitArray */
  toBits: function(str, _url) {
    str = str.replace(/\s|=/g,'');
    var out = [], i, bits=0, c = sjcl.codec.base64._chars, ta=0, x;
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; i<str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base64!");
      }
      if (bits > 26) {
        bits -= 26;
        out.push(ta ^ x>>>bits);
        ta  = x << (32-bits);
      } else {
        bits += 6;
        ta ^= x << (32-bits);
      }
    }
    if (bits&56) {
      out.push(sjcl.bitArray.partial(bits&56, ta, 1));
    }
    return out;
  }
};

sjcl.codec.base64url = {
  fromBits: function (arr) { return sjcl.codec.base64.fromBits(arr,1,1); },
  toBits: function (str) { return sjcl.codec.base64.toBits(str,1); }
};


/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

 /** @namespace UTF-8 strings */
 sjcl.codec.utf8String = { /** Convert from a bitArray to a UTF-8 string. */
  fromBits: function(arr) {
    var out = "",
    bl = sjcl.bitArray.bitLength(arr),
    i, tmp;
    for (i = 0; i < bl / 8; i++) {
      if ((i & 3) === 0) {
        tmp = arr[i / 4];
      }
      out += String.fromCharCode(tmp >>> 24);
      tmp <<= 8;
    }
    return decodeURIComponent(escape(out));
  },

  /** Convert from a UTF-8 string to a bitArray. */
  toBits: function(str) {
    str = unescape(encodeURIComponent(str));
    var out = [],
    i, tmp = 0;
    for (i = 0; i < str.length; i++) {
      tmp = tmp << 8 | str.charCodeAt(i);
      if ((i & 3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i & 3) {
      out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
    }
    return out;
  }
};

/** @fileOverview Password-based key-derivation function, version 2.0.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** Password-Based Key-Derivation Function, version 2.0.
 *
 * Generate keys from passwords using PBKDF2-HMAC-SHA256.
 *
 * This is the method specified by RSA's PKCS #5 standard.
 *
 * @param {bitArray|String} password  The password.
 * @param {bitArray} salt The salt.  Should have lots of entropy.
 * @param {Number} [count=1000] The number of iterations.  Higher numbers make the function slower but more secure.
 * @param {Number} [length] The length of the derived key.  Defaults to the
                            output size of the hash function.
 * @param {Object} [Prff=sjcl.misc.hmac] The pseudorandom function family.
 * @return {bitArray} the derived key.
 */
 sjcl.misc.pbkdf2 = function (password, salt, count, length, Prff) {
  count = count || 1000;
  
  if (length < 0 || count < 0) {
    throw sjcl.exception.invalid("invalid params to pbkdf2");
  }
  
  if (typeof password === "string") {
    password = sjcl.codec.utf8String.toBits(password);
  }
  
  Prff = Prff || sjcl.misc.hmac;
  
  var prf = new Prff(password),
  u, ui, i, j, k, out = [], b = sjcl.bitArray;

  for (k = 1; 32 * out.length < (length || 1); k++) {
    u = ui = prf.encrypt(b.concat(salt,[k]));
    
    for (i=1; i<count; i++) {
      ui = prf.encrypt(ui);
      for (j=0; j<ui.length; j++) {
        u[j] ^= ui[j];
      }
    }
    
    out = out.concat(u);
  }

  if (length) { out = b.clamp(out, length); }

  return out;
};

/** @fileOverview HMAC implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** HMAC with the specified hash function.
 * @constructor
 * @param {bitArray} key the key for HMAC.
 * @param {Object} [hash=sjcl.hash.sha256] The hash function to use.
 */

// These functions are obfuscated for CS255, since you will be implementing HMAC yourself.
sjcl.misc.hmac=function(a,b){
  this.M=b=b||sjcl.hash.sha256;var c=[[],[]],d=b.prototype.blockSize/32;
  this.l=[new b,new b];if(a.length>d)a=b.hash(a);
  for(b=0;b<d;b++){c[0][b]=a[b]^0x36363636;c[1][b]=a[b]^0x5C5C5C5C}
    this.l[0].update(c[0]);this.l[1].update(c[1]);
};
sjcl.misc.hmac.prototype.encrypt=sjcl.misc.hmac.prototype.mac=function(a,b){
  a=(new this.M(this.l[0])).update(a,b).finalize();
  return(new this.M(this.l[1])).update(a).finalize()
};

/** @fileOverview Javascript SHA-256 implementation.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * Special thanks to Aldo Cortesi for pointing out several bugs in
 * this code.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Context for a SHA-256 operation in progress.
 * @constructor
 * @class Secure Hash Algorithm, 256 bits.
 */
 sjcl.hash.sha256 = function (hash) {
  if (!this._key[0]) { this._precompute(); }
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};

/**
 * Hash a string or an array of words.
 * @static
 * @param {bitArray|String} data the data to hash.
 * @return {bitArray} The hash value, an array of 16 big-endian words.
 */
 sjcl.hash.sha256.hash = function (data) {
  return (new sjcl.hash.sha256()).update(data).finalize();
};

sjcl.hash.sha256.prototype = {
  /**
   * The hash's block size, in bits.
   * @constant
   */
   blockSize: 512,
   
  /**
   * Reset the hash state.
   * @return this
   */
   reset:function () {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  
  /**
   * Input several words to the hash.
   * @param {bitArray|String} data the data to hash.
   * @return this
   */
   update: function (data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data),
    ol = this._length,
    nl = this._length = ol + sjcl.bitArray.bitLength(data);
    for (i = 512+ol & -512; i <= nl; i+= 512) {
      this._block(b.splice(0,16));
    }
    return this;
  },
  
  /**
   * Complete hashing and output the hash value.
   * @return {bitArray} The hash value, an array of 8 big-endian words.
   */
   finalize:function () {
    var i, b = this._buffer, h = this._h;

    // Round out and push the buffer
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1,1)]);
    
    // Round out the buffer to a multiple of 16 words, less the 2 length words.
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }
    
    // append the length
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);

    while (b.length) {
      this._block(b.splice(0,16));
    }

    this.reset();
    return h;
  },

  /**
   * The SHA-256 initialization vector, to be precomputed.
   * @private
   */
   _init:[],
  /*
  _init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
  */
  
  /**
   * The SHA-256 hash key, to be precomputed.
   * @private
   */
   _key:[],
  /*
  _key:
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
     */


  /**
   * Function to precompute _init and _key.
   * @private
   */
   _precompute: function () {
    var i = 0, prime = 2, factor;

    function frac(x) { return (x-Math.floor(x)) * 0x100000000 | 0; }

    outer: for (; i<64; prime++) {
      for (factor=2; factor*factor <= prime; factor++) {
        if (prime % factor === 0) {
          // not a prime
          continue outer;
        }
      }
      
      if (i<8) {
        this._init[i] = frac(Math.pow(prime, 1/2));
      }
      this._key[i] = frac(Math.pow(prime, 1/3));
      i++;
    }
  },
  
  /**
   * Perform one cycle of SHA-256.
   * @param {bitArray} words one block of words.
   * @private
   */
   _block:function (words) {  
    var i, tmp, a, b,
    w = words.slice(0),
    h = this._h,
    k = this._key,
    h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3],
    h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];

    /* Rationale for placement of |0 :
     * If a value can overflow is original 32 bits by a factor of more than a few
     * million (2^23 ish), there is a possibility that it might overflow the
     * 53-bit mantissa and lose precision.
     *
     * To avoid this, we clamp back to 32 bits by |'ing with 0 on any value that
     * propagates around the loop, and on the hash state h[].  I don't believe
     * that the clamps on h4 and on h0 are strictly necessary, but it's close
     * (for h4 anyway), and better safe than sorry.
     *
     * The clamps on h[] are necessary for the output to be correct even in the
     * common case and for short inputs.
     */
     for (i=0; i<64; i++) {
      // load up the input word for this round
      if (i<16) {
        tmp = w[i];
      } else {
        a   = w[(i+1 ) & 15];
        b   = w[(i+14) & 15];
        tmp = w[i&15] = ((a>>>7  ^ a>>>18 ^ a>>>3  ^ a<<25 ^ a<<14) + 
         (b>>>17 ^ b>>>19 ^ b>>>10 ^ b<<15 ^ b<<13) +
         w[i&15] + w[(i+9) & 15]) | 0;
      }
      
      tmp = (tmp + h7 + (h4>>>6 ^ h4>>>11 ^ h4>>>25 ^ h4<<26 ^ h4<<21 ^ h4<<7) +  (h6 ^ h4&(h5^h6)) + k[i]); // | 0;
      
      // shift register
      h7 = h6; h6 = h5; h5 = h4;
      h4 = h3 + tmp | 0;
      h3 = h2; h2 = h1; h1 = h0;

      h0 = (tmp +  ((h1&h2) ^ (h3&(h1^h2))) + (h1>>>2 ^ h1>>>13 ^ h1>>>22 ^ h1<<30 ^ h1<<19 ^ h1<<10)) | 0;
    }

    h[0] = h[0]+h0 | 0;
    h[1] = h[1]+h1 | 0;
    h[2] = h[2]+h2 | 0;
    h[3] = h[3]+h3 | 0;
    h[4] = h[4]+h4 | 0;
    h[5] = h[5]+h5 | 0;
    h[6] = h[6]+h6 | 0;
    h[7] = h[7]+h7 | 0;
  }
};


// This is the initialization
SetupUsernames();
LoadKeys();
AddElements();
UpdateKeysTable();
RegisterChangeEvents();

console.log("CS255 script finished loading.");

// Stub for phantom.js (http://phantomjs.org/)
if (typeof phantom !== "undefined") {
  console.log("Hello! You're running in phantom.js.");
  // Add any function calls you want to run.
  phantom.exit();
}
