package org.siic.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class WelcomeController {

    @GetMapping
    public String welcome() {
        return "   _____ ______________    _____ ______________  ______  ____________  __\n" +
                "  / ___//  _/  _/ ____/   / ___// ____/ ____/ / / / __ \\/  _/_  __/\\ \\/ /\n" +
                "  \\__ \\ / / / // /  ______\\__ \\/ __/ / /   / / / / /_/ // /  / /    \\  /\n" +
                " ___/ // /_/ // /__/_____/__/ / /___/ /___/ /_/ / _, _// /  / /     / /\n" +
                "/____/___/___/\\____/    /____/_____/\\____/\\____/_/ |_/___/ /_/     /_/\n";
    }
}
