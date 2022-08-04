// MegaBot by Nebula! Made for Nathan's 4s chat server
// This code is overly scuffed as there no API
// It just listens for messages

// On load
msgBox.append(
    '<div><span class="user_message" style="color:#FF7000">Loaded MegaBot! Use !help for a list of commands. I\'m developed by Nebula, thanks for using! :3</span></div>'
);
msgBox[0].scrollTop = msgBox[0].scrollHeight;
var megabotInjected = true;

// Variables
var botTitle =
    '<div><span class="user_name" style="color:#FF7000">MegaBot [BOT]</span> : <span class="user_message">';
var lfmApiKey = "4a9f5581a9cdf20a699f540ac52a95c9"; // last.fm keys aren't even secret, and this isn't my key
var urlRegex = /(https?:\/\/[^\s]+)/g;
var textColor;
if (window.location.pathname.includes("/old")) {
    textColor = "#000000";
} else {
    textColor = "#FFFFFF";
}

// Main bot loop
setInterval(function () {
    var message = msgBox.find("div:gt(0):last").html();
    message = String(
        message.split(" : ")[1].split(">")[1].split("<")[0].toLowerCase()
    );

    var messageNoLower = msgBox.find("div:gt(0):last").html();
    messageNoLower = String(
        messageNoLower.split(" : ")[1].split(">")[1].split("<")[0]
    );

    // Check for youtube links and give data about them
    if (
        messageNoLower.includes("youtube.com") ||
        messageNoLower.includes("youtu.be")
    ) {
        messageNoLower.replace(urlRegex, function (url) {
            id = url.split("//")[1].split("/")[1].replace("watch?v=", "");

            $.getJSON(
                `https://returnyoutubedislikeapi.com/votes?videoId=${id}`,
                function (data) {
                    msgBox.append(
                        botTitle +
                            "That's a cool YouTube link! Here's some stats about that video:</span></div>"
                    );
                    msgBox.append(
                        `<div style="color:${textColor}">- ${data.likes} likes</div>`
                    );
                    msgBox.append(
                        `<div style="color:${textColor}">- ${data.dislikes} dislikes</div>`
                    );
                    msgBox.append(
                        `<div style="color:${textColor}">- ${data.viewCount} views</div>`
                    );
                    msgBox[0].scrollTop = msgBox[0].scrollHeight;
                }
            );
        });
    }

    // Help command
    if (message == "!help") {
        msgBox.append(botTitle + "Here are my commands!" + "</span></div>");
        msgBox.append(
            `<div style="color:${textColor}">- !ticker <crypto> | Get info for a cryptocurrency (eg. Bitcoin).</div>`
        );
        msgBox.append(
            `<div style="color:${textColor}">- !fact | Get a random useless fact.</div>`
        );
        msgBox.append(
            `<div style="color:${textColor}">- !define [word(s)] | Get a definition for a word(s) from Urban Dictionary.</div>`
        );
        msgBox.append(
            `<div style="color:${textColor}">- !lastfm [top|info] [username] | Get data from last.fm.</div>`
        );
        msgBox.append(
            `<div style="color:${textColor}">- !neko [cuddle|meow|pat|hug|meow|neko|woof] | Fetch an image from nekos.life.</div>`
        );
        msgBox.append(
            `<div style="color:${textColor}">- !online | Get online members.</div>`
        );
        msgBox[0].scrollTop = msgBox[0].scrollHeight;
    }

    // Ticker command
    if (message.startsWith("!ticker ")) {
        cmd = message.replace("!ticker ", "");
        $.getJSON(
            "https://api.coingecko.com/api/v3/coins/" + cmd + "/tickers",
            function (data) {
                msgBox.append(
                    botTitle +
                        data.name +
                        " is currently at $" +
                        data.tickers[0].last +
                        " USD (" +
                        data.tickers[0].market.name +
                        ").</span></div>"
                );
                msgBox[0].scrollTop = msgBox[0].scrollHeight;
            }
        );
    }

    // Random fact command
    if (message == "!fact") {
        $.getJSON("https://uselessfacts.jsph.pl/random.json", function (data) {
            msgBox.append(
                botTitle +
                    "Here's your random useless fact: " +
                    data.text +
                    "</span></div>"
            );
            msgBox[0].scrollTop = msgBox[0].scrollHeight;
        });
    }

    // Urban Dictionary command
    if (message.startsWith("!define ")) {
        cmd = message.replace("!define ", "");
        $.getJSON(
            "https://api.urbandictionary.com/v0/define?term=" + cmd,
            function (data) {
                msgBox.append(
                    botTitle +
                        "Result for " +
                        cmd +
                        ": " +
                        data.list[0].definition +
                        "</span></div>"
                );
                msgBox[0].scrollTop = msgBox[0].scrollHeight;
            }
        );
    }

    // lastfm command
    if (message.startsWith("!lastfm top ")) {
        cmd = message.replace("!lastfm top ", "");
        $.getJSON(
            `http://ws.audioscrobbler.com/2.0/?method=user.getTopTracks&user=${cmd}&api_key=${lfmApiKey}&limit=5&format=json`,
            function (data) {
                msgBox.append(
                    `${botTitle}${cmd}'s top 5 tracks are:</span></div>`
                );
                msgBox.append(
                    `<div style="color:${textColor}">1. ${data.toptracks.track[0].name} by ${data.toptracks.track[0].artist.name} (${data.toptracks.track[0].playcount} plays)</div>`
                );
                msgBox.append(
                    `<div style="color:${textColor}">2. ${data.toptracks.track[1].name} by ${data.toptracks.track[1].artist.name} (${data.toptracks.track[1].playcount} plays)</div>`
                );
                msgBox.append(
                    `<div style="color:${textColor}">3. ${data.toptracks.track[2].name} by ${data.toptracks.track[2].artist.name} (${data.toptracks.track[2].playcount} plays)</div>`
                );
                msgBox.append(
                    `<div style="color:${textColor}">4. ${data.toptracks.track[3].name} by ${data.toptracks.track[3].artist.name} (${data.toptracks.track[3].playcount} plays)</div>`
                );
                msgBox.append(
                    `<div style="color:${textColor}">5. ${data.toptracks.track[4].name} by ${data.toptracks.track[4].artist.name} (${data.toptracks.track[4].playcount} plays)</div>`
                );
                msgBox[0].scrollTop = msgBox[0].scrollHeight;
            }
        );
    } else if (message.startsWith("!lastfm info ")) {
        cmd = message.replace("!lastfm info ", "");
        $.getJSON(
            `http://ws.audioscrobbler.com/2.0/?method=user.getInfo&user=${cmd}&api_key=${lfmApiKey}&format=json`,
            function (data) {
                msgBox.append(`${botTitle}Info about ${cmd}:</span></div>`);
                msgBox.append(
                    `<div style="color:${textColor}">- ${data.user.playcount} tracks scrobbled.</div>`
                );
                msgBox.append(
                    `<div style="color:${textColor}">- They're from the ${data.user.country}.</div>`
                );
                msgBox.append(
                    `<div style="color:${textColor}">- They have ${data.user.playlists} playlists.</div>`
                );
                msgBox.append(
                    `<div style="color:${textColor}">- See more <a href='${data.user.url}'>on their profile</a>.</div>`
                );
                msgBox[0].scrollTop = msgBox[0].scrollHeight;
            }
        );
    } else if (message.startsWith("!lastfm ")) {
        msgBox.append(
            `${botTitle}Wrong usage! Correct usage: !lastfm <top> <username></span></div>`
        );
    } else if (message == "!lastfm") {
        msgBox.append(
            `${botTitle}Usage: !lastfm [top] [username]</span></div>`
        );
    }

    // Neko command
    if (message.startsWith("!neko ")) {
        cmd = message.replace("!neko ", "");

        const allowedEndpoints = [
            "woof",
            "cuddle",
            "meow",
            "pat",
            "hug",
            "meow",
            "neko",
        ];
        if (allowedEndpoints.includes(cmd)) {
            $.getJSON(`https://nekos.life/api/v2/img/${cmd}`, function (data) {
                msgBox.append(
                    `${botTitle}Here's the ${cmd} you wanted!</span></div>`
                );
                msgBox.append(`<img src="${data.url}" width="128px"></img>`);
                setTimeout(function () {
                    msgBox[0].scrollTop = msgBox[0].scrollHeight;
                }, 750);
            });
        } else {
            msgBox.append(
                `${botTitle}The query ${cmd} is invalid.</span></div>`
            );
        }
    } else if (message == "!neko") {
        $.getJSON(`https://nekos.life/api/v2/img/neko`, function (data) {
            msgBox.append(
                `${botTitle}Here's the neko you wanted!</span></div>`
            );
            msgBox.append(`<img src="${data.url}" width="128px"></img>`);

            setTimeout(function () {
                msgBox[0].scrollTop = msgBox[0].scrollHeight;
            }, 750);
        });
    }

    // Online command
    if (message == "!online") {
        msgBox.append(
            botTitle +
                `Getting online members... <script>var theName = document.getElementById('name').value; msgBox.append('${botTitle}' + theName + ' is online:</span></div>');</script></span></div>`
        );
        msgBox[0].scrollTop = msgBox[0].scrollHeight;
    }
}, 1000);
