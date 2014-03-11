component extends="cfselenium.CFSeleniumTestCase" displayName="raw" {

    public void function beforeTests() {
        browserUrl = "enter_starting_url_here";
        super.beforeTests();
        selenium.setTimeout(30000);
    }

    public void function testRaw() {
        selenium.open("/esapi4cf-development/esapi4cf/samples/tutorials/login.cfm?x=k1l6jRzCwioGnT5kzlUIrSIDuPQli6icyv1t%2BfSTGfpI01%2Fp%2FRf4RAvEG7kosnASA218dbN5fvadx1RYe3MZwsJK1z%2FlpOT1s9FzQwUwcnaNtnbkjGN%2BTGzkY4FZd%2Fi6mZVdrqXqm5wkgkiurSyi000gKRsup4%2Fpt%2F23M2VPfu8%3D");
        selenium.type("id=accountName", "admin");
        selenium.type("id=password", "Admin123");
        selenium.click("id=loginButton");
        selenium.waitForPageToLoad("30000");
        assertEquals("Attempt to login with an insecure request", selenium.getText("css=div.alert.alert-danger"));
    }
}
