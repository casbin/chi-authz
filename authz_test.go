package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin"
	"github.com/go-chi/chi"
)

func testAuthzRequest(t *testing.T, router *chi.Mux, user string, path string, method string, code int) {
	r, _ := http.NewRequest(method, path, nil)
	r.SetBasicAuth(user, "123")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	if w.Code != code {
		t.Errorf("%s, %s, %s: %d, supposed to be %d", user, path, method, w.Code, code)
	}
}

func TestBasic(t *testing.T) {
	router := chi.NewRouter()

	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	router.Use(Authorizer(e))

	// Here we use HTTP basic authentication as the way to get the logged-in user name
	// For simplicity, the credential is not verified, you should implement and use your own
	// authentication before the authorization.
	// In this example, we assume "alice:123" is a legal user.
	router.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	testAuthzRequest(t, router, "alice", "/dataset1/resource1", "GET", http.StatusOK)
	testAuthzRequest(t, router, "alice", "/dataset1/resource1", "POST", http.StatusOK)
	testAuthzRequest(t, router, "alice", "/dataset1/resource2", "GET", http.StatusOK)
	testAuthzRequest(t, router, "alice", "/dataset1/resource2", "POST", http.StatusForbidden)
}

func TestPathWildcard(t *testing.T) {
	router := chi.NewRouter()

	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	router.Use(Authorizer(e))

	// Here we use HTTP basic authentication as the way to get the logged-in user name
	// For simplicity, the credential is not verified, you should implement and use your own
	// authentication before the authorization.
	// In this example, we assume "bob:123" is a legal user.
	router.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	testAuthzRequest(t, router, "bob", "/dataset2/resource1", "GET", http.StatusOK)
	testAuthzRequest(t, router, "bob", "/dataset2/resource1", "POST", http.StatusOK)
	testAuthzRequest(t, router, "bob", "/dataset2/resource1", "DELETE", http.StatusOK)
	testAuthzRequest(t, router, "bob", "/dataset2/resource2", "GET", http.StatusOK)
	testAuthzRequest(t, router, "bob", "/dataset2/resource2", "POST", http.StatusForbidden)
	testAuthzRequest(t, router, "bob", "/dataset2/resource2", "DELETE", http.StatusForbidden)

	testAuthzRequest(t, router, "bob", "/dataset2/folder1/item1", "GET", http.StatusForbidden)
	testAuthzRequest(t, router, "bob", "/dataset2/folder1/item1", "POST", http.StatusOK)
	testAuthzRequest(t, router, "bob", "/dataset2/folder1/item1", "DELETE", http.StatusForbidden)
	testAuthzRequest(t, router, "bob", "/dataset2/folder1/item2", "GET", http.StatusForbidden)
	testAuthzRequest(t, router, "bob", "/dataset2/folder1/item2", "POST", http.StatusOK)
	testAuthzRequest(t, router, "bob", "/dataset2/folder1/item2", "DELETE", http.StatusForbidden)
}

func TestRBAC(t *testing.T) {
	router := chi.NewRouter()

	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	router.Use(Authorizer(e))

	// Here we use HTTP basic authentication as the way to get the logged-in user name
	// For simplicity, the credential is not verified, you should implement and use your own
	// authentication before the authorization.
	// In this example, we assume "cathy:123" is a legal user.
	router.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// cathy can access all /dataset1/* resources via all methods because it has the dataset1_admin role.
	testAuthzRequest(t, router, "cathy", "/dataset1/item", "GET", http.StatusOK)
	testAuthzRequest(t, router, "cathy", "/dataset1/item", "POST", http.StatusOK)
	testAuthzRequest(t, router, "cathy", "/dataset1/item", "DELETE", http.StatusOK)
	testAuthzRequest(t, router, "cathy", "/dataset2/item", "GET", http.StatusForbidden)
	testAuthzRequest(t, router, "cathy", "/dataset2/item", "POST", http.StatusForbidden)
	testAuthzRequest(t, router, "cathy", "/dataset2/item", "DELETE", http.StatusForbidden)

	// delete all roles on user cathy, so cathy cannot access any resources now.
	e.DeleteRolesForUser("cathy")

	testAuthzRequest(t, router, "cathy", "/dataset1/item", "GET", http.StatusForbidden)
	testAuthzRequest(t, router, "cathy", "/dataset1/item", "POST", http.StatusForbidden)
	testAuthzRequest(t, router, "cathy", "/dataset1/item", "DELETE", http.StatusForbidden)
	testAuthzRequest(t, router, "cathy", "/dataset2/item", "GET", http.StatusForbidden)
	testAuthzRequest(t, router, "cathy", "/dataset2/item", "POST", http.StatusForbidden)
	testAuthzRequest(t, router, "cathy", "/dataset2/item", "DELETE", http.StatusForbidden)
}
