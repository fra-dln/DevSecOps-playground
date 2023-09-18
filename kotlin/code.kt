import io.ktor.application.*
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.jackson.jackson
import io.ktor.request.receiveParameters
import io.ktor.response.respondText
import io.ktor.routing.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.sessions.*

data class User(val username: String, val password: String)

val users = listOf(User("user1", "password1"), User("user2", "password2"))

data class UserSession(val username: String)

fun main() {
    embeddedServer(Netty, port = 8080) {
        install(ContentNegotiation) {
            jackson { } // JSON support (optional)
        }

        install(Sessions) {
            cookie<UserSession>("user_session") {
                cookie.path = "/"
                cookie.extensions["SameSite"] = "lax"
            }
        }

        install(StatusPages) {
            exception<Throwable> { cause ->
                call.respondText("An internal server error occurred: ${cause.localizedMessage}", ContentType.Text.Plain, HttpStatusCode.InternalServerError)
            }
        }

        routing {
            route("/") {
                get {
                    call.respondText("Welcome to my website!", ContentType.Text.Html)
                }

                get("/about") {
                    call.respondText("This is the about page.", ContentType.Text.Html)
                }

                get("/contact") {
                    call.respondText("Contact us at contact@example.com.", ContentType.Text.Html)
                }

                get("/login") {
                    call.respondText(getLoginPage(), ContentType.Text.Html)
                }

                post("/login") {
                    val postParameters = call.receiveParameters()
                    val username = postParameters["username"]
                    val password = postParameters["password"]
                    val user = users.find { it.username == username && it.password == password }

                    if (user != null) {
                        call.sessions.set(UserSession(username))
                        call.respondText("Login successful, $username!", ContentType.Text.Html)
                    } else {
                        call.respondText("Login failed. Please try again.", ContentType.Text.Html)
                    }
                }

                authenticate {
                    get("/dashboard") {
                        val session = call.sessions.get<UserSession>()
                        if (session != null) {
                            call.respondText("Welcome to the dashboard, ${session.username}!", ContentType.Text.Html)
                        } else {
                            call.respondText("Unauthorized access. Please log in.", ContentType.Text.Html, HttpStatusCode.Unauthorized)
                        }
                    }
                }
            }
        }
    }.start(wait = true)
}

fun getLoginPage(): String {
    return """
        <html>
        <head>
            <title>Login</title>
        </head>
        <body>
            <h2>Login</h2>
            <form method="post" action="/login">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required><br>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required><br>
                <input type="submit" value="Login">
            </form>
        </body>
        </html>
    """.trimIndent()
}
