import javax.naming.directory.DirContext;
import org.springframework.web.bind.annotation.GetMapping;

class UserController {
    @GetMapping("/user")
    Object findUser(DirContext ctx, String username) throws Exception {
        return ctx.search("ou=people", "(uid=" + username + ")", null);
    }
}
