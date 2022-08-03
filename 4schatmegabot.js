// Load the bot with the following script:
// <script>$.getScript("https://static.itsnebula.net/4schatmegabot.js");</script>

msgBox.append(
    '<div><span class="user_message" style="color:#0000ff">Hi there, I\'m MegaBot! Use <span style="font-weight: 600">!help</span> for a list of commands I\'m developed by Nebula, thanks for using! :3</span></div>'
);
msgBox[0].scrollTop = msgBox[0].scrollHeight;

var botTitle =
    '<div><span class="user_name" style="color:#0000ff">MegaBot <div style="font-weight: 600">[BOT]</div></span> : <span class="user_message">';

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
}, 1000);
