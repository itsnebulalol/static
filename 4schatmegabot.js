// Load the bot with the following script:
// <script>$.getScript("https://static.itsnebula.net/4schatmegabot.js");</script>

// On load
msgBox.append(
    '<div><span class="user_message" style="color:#0000ff">Hi there, I\'m MegaBot! Use <span style="font-weight: 600">!help</span> for a list of commands I\'m developed by Nebula, thanks for using! :3</span></div>'
);
msgBox[0].scrollTop = msgBox[0].scrollHeight;

// Variables
var botTitle =
    '<div><span class="user_name" style="color:#0000ff">MegaBot [BOT]</span> : <span class="user_message">';
var lfmApiKey = "4a9f5581a9cdf20a699f540ac52a95c9";

// Main bot loop
setInterval(function () {
    var message = msgBox.find("div:gt(0):last").html();
    message = String(
        message.split(" : ")[1].split(">")[1].split("<")[0].toLowerCase()
    );

    // Help command
    if (message == "!help") {
        msgBox.append(botTitle + "Here are my commands!" + "</span></div>");
        msgBox.append(
            '<div style="color:#000000">  - !ticker <crypto> -- Get info for a cryptocurrency (eg. Bitcoin).</div>'
        );
        msgBox.append(
            '<div style="color:#000000">  - !fact -- Get a random useless fact.</div>'
        );
        msgBox.append(
            '<div style="color:#000000">  - !define <word(s)> -- Get a definition for a word(s) from Urban Dictionary.</div>'
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
            `http://ws.audioscrobbler.com/2.0/?method=user.getTopTracks&user=${cmd}&api_key=${lfmApiKey}&limit=10&format=json`,
            function (data) {
                msgBox.append(
                    `${botTitle}${cmd}'s top 5 tracks are:</span></div>`
                );
                msgBox.append(
                    `<div style="color:#000000">  1. ${data.toptracks.track[0].name} by ${data.toptracks.track[0].artist.name} (${data.toptracks.track[0].playcount} plays)</div>`
                );
                msgBox.append(
                    `<div style="color:#000000">  2. ${data.toptracks.track[1].name} by ${data.toptracks.track[1].artist.name} (${data.toptracks.track[1].playcount} plays)</div>`
                );
                msgBox.append(
                    `<div style="color:#000000">  3. ${data.toptracks.track[2].name} by ${data.toptracks.track[2].artist.name} (${data.toptracks.track[2].playcount} plays)</div>`
                );
                msgBox.append(
                    `<div style="color:#000000">  4. ${data.toptracks.track[3].name} by ${data.toptracks.track[3].artist.name} (${data.toptracks.track[3].playcount} plays)</div>`
                );
                msgBox.append(
                    `<div style="color:#000000">  5. ${data.toptracks.track[4].name} by ${data.toptracks.track[4].artist.name} (${data.toptracks.track[4].playcount} plays)</div>`
                );
                msgBox[0].scrollTop = msgBox[0].scrollHeight;
            }
        );
    }
}, 1000);
