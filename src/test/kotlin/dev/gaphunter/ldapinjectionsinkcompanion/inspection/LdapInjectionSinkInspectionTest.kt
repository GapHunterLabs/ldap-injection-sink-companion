package dev.gaphunter.ldapinjectionsinkcompanion.inspection

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class LdapInjectionSinkInspectionTest : BasePlatformTestCase() {

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(LdapInjectionSinkInspection::class.java)
    }

    fun `test a request parameter concatenated into an LDAP filter is flagged`() {
        myFixture.configureByText(
            "UserController.java",
            """
            import javax.naming.directory.DirContext;
            import org.springframework.web.bind.annotation.GetMapping;

            class UserController {
                @GetMapping("/user")
                Object findUser(DirContext ctx, String username) throws Exception {
                    return ctx.search("ou=people", "(uid=" + username + ")", null);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CWE-90") == true })
    }

    fun `test a request parameter passed directly as the filter is flagged`() {
        myFixture.configureByText(
            "RawController.java",
            """
            import javax.naming.directory.DirContext;
            import org.springframework.web.bind.annotation.GetMapping;

            class RawController {
                @GetMapping("/raw")
                Object run(DirContext ctx, String userFilter) throws Exception {
                    return ctx.search("ou=people", userFilter, null);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CWE-90") == true })
    }

    fun `test a hardcoded LDAP filter with no taint is not flagged`() {
        myFixture.configureByText(
            "SafeController.java",
            """
            import javax.naming.directory.DirContext;
            import org.springframework.web.bind.annotation.GetMapping;

            class SafeController {
                @GetMapping("/safe")
                Object run(DirContext ctx, String unused) throws Exception {
                    return ctx.search("ou=people", "(uid=admin)", null);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-90") == true })
    }

    fun `test a non-DirContext type with a coincidentally named search method is not flagged`() {
        myFixture.configureByText(
            "OtherSearch.java",
            """
            import org.springframework.web.bind.annotation.GetMapping;

            class MySearcher {
                Object search(String base, String filter, Object ignored) { return filter; }
            }

            class OtherSearch {
                @GetMapping("/x")
                Object handle(String filter) {
                    MySearcher searcher = new MySearcher();
                    return searcher.search("base", filter, null);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-90") == true })
    }

    fun `test a non-endpoint method with the same shape is not flagged`() {
        myFixture.configureByText(
            "Helper.java",
            """
            import javax.naming.directory.DirContext;

            class Helper {
                Object run(DirContext ctx, String username) throws Exception {
                    return ctx.search("ou=people", "(uid=" + username + ")", null);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-90") == true })
    }
}
