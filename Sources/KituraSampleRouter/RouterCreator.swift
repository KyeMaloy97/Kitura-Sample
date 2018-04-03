/**
 * Copyright IBM Corporation 2016
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

// KituraSample shows examples for creating custom routes.

import Foundation

import Kitura
import KituraMarkdown
import KituraStencil // required for using StencilTemplateEngine
import Stencil // required for adding a Stencil namespace to StencilTemplateEngine
import KituraWebSocket
import SwiftJWT
import HTMLEntities

import LoggerAPI
import HeliumLogger

#if os(Linux)
    import Glibc
#endif
// Error handling example

enum SampleError: Error {
    case sampleError
}

let customParameterHandler: RouterHandler = { request, response, next in
    let id = request.parameters["id"] ?? "unknown"
    response.send("\(id)|").status(.OK)
    next()
}

class CustomParameterMiddleware: RouterMiddleware {
    func handle(request: RouterRequest, response: RouterResponse, next: @escaping () -> Void) {
        do {
            try customParameterHandler(request, response, next)
        } catch {
            Log.error("customParameterHandler returned error: \(error)")
        }

    }
}

extension SampleError: CustomStringConvertible {
    var description: String {
        switch self {
        case .sampleError:
            return "Example of error being set"
        }
    }
}

public let users: [User] = [
    User(username: "admin", password: "password", admin: true),
    User(username: "user1", password: "defaultPassword", admin: false),
    User(username: "expired", password: "expired", admin: false)
]

public struct RouterCreator {
    public static func create() -> Router {
        let router = Router()

        /**
         * RouterMiddleware can be used for intercepting requests and handling custom behavior
         * such as authentication and other routing
         */
        class BasicAuthMiddleware: RouterMiddleware {
            func handle(request: RouterRequest, response: RouterResponse, next: @escaping () -> Void) {
                let authString = request.headers["Authorization"]
                Log.info("Authorization: \(String(describing: authString))")
                // Check authorization string in database to approve the request if fail
                // response.error = NSError(domain: "AuthFailure", code: 1, userInfo: [:])
                next()
            }
        }

        // Variable to post/put data to (just for sample purposes)
        var name: String?

        // This route executes the echo middleware
        router.all(middleware: BasicAuthMiddleware())

        router.all("/static", middleware: StaticFileServer())
        router.all("/chat", middleware: StaticFileServer(path: "./chat"))
        router.all("/jwt", middleware: StaticFileServer(path: "/jwt"))
        
        router.get("/hello") { _, response, next in
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            let fName = name ?? "World"
            try response.send("Hello \(fName), from Kitura!").end()
        }

        // This route accepts POST requests
        router.post("/hello") {request, response, next in
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            name = try request.readString()
            try response.send("Got a POST request").end()
        }
        
        router.get("/login") { request, response, next in
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            try response.render("index", context: [:])
            next()
        }
        
        router.post("/submit") { request, response, next in
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            guard let data = try request.readString() else {
                try response.send("Unable to parse input from form.").end()
                next()
                return
            }
            let stringArr = data.components(separatedBy: "&")
            var attemptedUser = User(username: String(describing: stringArr[0].split(separator: "=").last!), password: String(describing: stringArr[1].split(separator: "=").last!), admin: false)
            
            for user in users {
                if attemptedUser.username == user.username {
                    if attemptedUser.password == user.password {
                        let authenticatedUser = user
                        
                        // Generate the JWT as they have been authorised as a user of the site.
                        let myKeyPath = URL.init(fileURLWithPath: getAbsolutePath(relativePath: "/jwt/jwtRS256.key")!)
                        var key: Data = try Data(contentsOf: myKeyPath, options: .alwaysMapped)
                        
                        // Create time objects for making the Issued At and Expires claim. Also makes a dud for showing
                        // what happens when you login with an expired token.
                        let time = NSDate().timeIntervalSince1970
                        let expireDate = NSDate().timeIntervalSince1970.advanced(by: 31557600.00) //Adds 1 year in seconds.
                        let dudExpire = NSDate().timeIntervalSince1970.nextDown
                        
                        // Create the JWT with a Header and a Claims object
                        var headers = Header([.typ:"JWT", .alg:"rsa256",])
                        var claims = Claims([.iss:"IBM", .name: authenticatedUser.username, .iat: time, .exp: expireDate])
                        // Make the token have an expired expiration date.
                        if authenticatedUser.username == "expired" {
                            claims[.exp] = dudExpire
                        }
                        var jwt = JWT(header: headers, claims: claims)
                        
                        
                        // Sign the JWT.
                        guard let signedJWT = try jwt.sign(using: .rs256(key, .privateKey)) else {
                            try response.send("Error creating/signing JWT.").end()
                            return
                        }
                        
                        let decoded = try! JWT.decode(signedJWT)
                        let printThis = String(describing: decoded!)
                        
                        response.headers["Set-Cookie"] = "jwt=\(signedJWT)"
                        try response.render("loggedin", context: ["decodedJWT": printThis, "token": signedJWT])
                        return
                    } else {
                        try response.render("index", context: ["reason":"Incorrect Credentials. Please try again."])
                    }
                }
            }
            
        }
        
        router.get("/secret") { request, response, next in
            let cookieFull = request.headers["Cookie"]
            let cookieArray = cookieFull?.split(separator: ";")
            var cookie = String()
            if cookieArray != nil {
                for item in cookieArray! {
                    if item.contains("jwt") {
                        let newArray = item.split(separator: "=")
                        cookie = String(describing: newArray[1])
                    }
                }
            }
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            
            let decoded = try JWT.decode(cookie)
            let claims = decoded?.validateClaims(issuer: "IBM")
            let claimsString = String(describing: claims!)
            print("ClaimsString: \(claimsString)")
            if claims != nil {
                switch claims! {
                    case .success:
                        try response.render("success", context: ["name": decoded?.claims.asDictionary["name"]])
                    default:
                        try response.render("failure", context: ["claims": claimsString])
                }
            } else {
                try response.render("failure", context: ["claims": claimsString])

            }
            
        }
        
        
        router.get("/print_jwt") { request, response, next in

            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            let myKeyPath = URL.init(fileURLWithPath: getAbsolutePath(relativePath: "/jwt/jwtRS256.key")!)
            var key: Data = try Data(contentsOf: myKeyPath, options: .alwaysMapped)
            var jwt = JWT(header: Header([.typ:"JWT", .alg:"rsa256", .cty:"JWE"]), claims: Claims([.name:"Kitura", .jti:"sbdabd762AA", .iss:"IBM", .aud:"anyone", .sub:"KituraSample", .iat:"03/15/2018", .exp:"03/15/2019", .nbf:"03/14/2018"]))
            guard let signedJWT = try jwt.sign(using: .rs256(key, .privateKey)) else {
                try response.send("Error creating/signing JWT.").end()
                return
            }
            let decoded = try JWT.decode(signedJWT)
            print(decoded!)

            try response.send(signedJWT).end()
        }

        // This route accepts PUT requests
        router.put("/hello") {request, response, next in
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            name = try request.readString()
            try response.send("Got a PUT request").end()
        }

        // This route accepts DELETE requests
        router.delete("/hello") {request, response, next in
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            name = nil
            try response.send("Got a DELETE request").end()
        }

        router.get("/error") { _, response, next in
            Log.error("Example of error being set")
            response.status(.internalServerError)
            response.error = SampleError.sampleError
            next()
        }

        // Redirection example
        router.get("/redir") { _, response, next in
            try response.redirect("http://www.ibm.com/us-en/")
            next()
        }

        // Reading parameters
        // Accepts user as a parameter
        router.get("/users/:user") { request, response, next in
            response.headers["Content-Type"] = "text/html"
            let p1 = request.parameters["user"] ?? "(nil)"
            try response.send(
                "<!DOCTYPE html><html><body>" +
                    "<b>User:</b> \(p1)" +
                "</body></html>\n\n").end()
        }

        // Uses multiple handler blocks
        router.get("/multi", handler: { request, response, next in
            response.send("I'm here!\n")
            next()
            }, { request, response, next in
                response.send("Me too!\n")
                next()
        })
        router.get("/multi") { request, response, next in
            try response.send("I come afterward..\n").end()
        }

        router.get("/user/:id", allowPartialMatch: false, middleware: CustomParameterMiddleware())
        router.get("/user/:id", handler: customParameterHandler)

        // add Stencil Template Engine with a extension with a custom tag
        let _extension = Extension()
        // from https://github.com/kylef/Stencil/blob/master/ARCHITECTURE.md#simple-tags
        _extension.registerSimpleTag("custom") { _ in
            return "Hello World"
        }

        let templateEngine = StencilTemplateEngine(extension: _extension)
        router.setDefault(templateEngine: templateEngine)
        router.add(templateEngine: templateEngine,
                   forFileExtensions: ["html"])

        // the example from https://github.com/kylef/Stencil
        let stencilContext: [String: Any] = [
            "articles": [
                [ "title": "Migrating from OCUnit to XCTest", "author": "Kyle Fuller" ],
                [ "title": "Memory Management with ARC", "author": "Kyle Fuller" ],
            ]
        ]

        router.get("/articles") { _, response, next in
            defer {
                next()
            }
            do {
                try response.render("document", context: stencilContext).end()
            } catch {
                Log.error("Failed to render template \(error)")
            }
        }

        router.get("/articles.html") { _, response, next in
            defer {
                next()
            }
            do {
                // we have to specify file extension here since it is not the extension of Stencil
                try response.render("document.html", context: stencilContext).end()
            } catch {
                Log.error("Failed to render template \(error)")
            }
        }

        router.get("/articles_subdirectory") { _, response, next in
            defer {
                next()
            }
            do {
                try response.render("subdirectory/documentInSubdirectory",
                                    context: stencilContext).end()
            } catch {
                Log.error("Failed to render template \(error)")
            }
        }

        router.get("/articles_include") { _, response, next in
            defer {
                next()
            }
            do {
                try response.render("includingDocument",
                                    context: stencilContext).end()
            } catch {
                Log.error("Failed to render template \(error)")
            }
        }

        router.get("/custom_tag_stencil") { _, response, next in
            defer {
                next()
            }
            do {
                try response.render("customTag", context: [:]).end()
            } catch {
                Log.error("Failed to render template \(error)")
            }
        }

        // Add KituraMarkdown as a TemplateEngine
        router.add(templateEngine: KituraMarkdown())

        router.get("/docs") { _, response, next in
            try response.render("/docs/index.md", context: [String:Any]())
            response.status(.OK)
            next()
        }

        router.get("/docs/*") { request, response, next in
            if request.urlURL.path != "/docs/" {
                try response.render(request.urlURL.path, context: [String:Any]())
                response.status(.OK)
            }
            next()
        }

        // Handles any errors that get set
        router.error { request, response, next in
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            let errorDescription: String
            if let error = response.error {
                errorDescription = "\(error)"
            } else {
                errorDescription = "Unknown error"
            }
            try response.send("Caught the error: \(errorDescription)").end()
        }


        // A custom Not found handler
        router.all { request, response, next in
            if  response.statusCode == .unknown  {
                // Remove this wrapping if statement, if you want to handle requests to / as well
                let path = request.urlURL.path
                if  path != "/" && path != ""  {
                    try response.status(.notFound).send("Route not found in Sample application!").end()
                }
            }
            next()
        }
        
        func getAbsolutePath(relativePath: String) -> String? {
            let fileManager = FileManager.default
            let currentPath = fileManager.currentDirectoryPath
            var filePath = currentPath + "/" + relativePath
            if fileManager.fileExists(atPath: filePath) {
                return filePath
            } else {
                let initialPath = #file
                let components = initialPath.characters.split(separator: "/").map(String.init)
                var searchDepth = 1
                while components.count >= searchDepth {
                    let currentDir = components[0..<components.count - searchDepth]
                    filePath = "/" + currentDir.joined(separator: "/") + "/" + relativePath
                    if fileManager.fileExists(atPath: filePath) {
                        return filePath
                    }
                    searchDepth += 1
                }
                return nil
            }
        }

        return router
    }
}
