package v2

import (
	"reflect"
	"testing"
)

func TestRuleResourceMatches(t *testing.T) {
	tests := []struct {
		name              string
		resources         []string
		requestedResource string
		want              bool
	}{
		{
			name:              "empty rule resources",
			requestedResource: "checks",
			want:              false,
		},
		{
			name:              "all resources",
			resources:         []string{ResourceAll},
			requestedResource: "checks",
			want:              true,
		},
		{
			name:              "does not match",
			resources:         []string{"checks"},
			requestedResource: "events",
			want:              false,
		},
		{
			name:              "matches",
			resources:         []string{"checks", "events"},
			requestedResource: "events",
			want:              true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Rule{
				Resources: tc.resources,
			}
			if got := r.ResourceMatches(tc.requestedResource); got != tc.want {
				t.Errorf("Rule.ResourceMatches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRuleResourceNameMatches(t *testing.T) {
	tests := []struct {
		name                  string
		resourceNames         []string
		requestedResourceName string
		want                  bool
	}{
		{
			name: "rule allows all names",
			requestedResourceName: "checks",
			want: true,
		},
		{
			name:          "rule only allows a specific name none specified in req",
			resourceNames: []string{"foo"},
			want:          false,
		},
		{
			name:                  "does not match",
			resourceNames:         []string{"foo"},
			requestedResourceName: "bar",
			want: false,
		},
		{
			name:                  "matches",
			resourceNames:         []string{"foo", "bar"},
			requestedResourceName: "bar",
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Rule{
				ResourceNames: tc.resourceNames,
			}
			if got := r.ResourceNameMatches(tc.requestedResourceName); got != tc.want {
				t.Errorf("Rule.ResourceNameMatches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRuleVerbMatches(t *testing.T) {
	tests := []struct {
		name          string
		verbs         []string
		requestedVerb string
		want          bool
	}{
		{
			name:          "empty rule verbs",
			requestedVerb: "get",
			want:          false,
		},
		{
			name:          "all verbs",
			verbs:         []string{VerbAll},
			requestedVerb: "get",
			want:          true,
		},
		{
			name:          "does not match",
			verbs:         []string{"create"},
			requestedVerb: "get",
			want:          false,
		},
		{
			name:          "matches",
			verbs:         []string{"create", "get"},
			requestedVerb: "get",
			want:          true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Rule{
				Verbs: tc.verbs,
			}
			if got := r.VerbMatches(tc.requestedVerb); got != tc.want {
				t.Errorf("Rule.VerbMatches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func Test_validateVerbs(t *testing.T) {
	tests := []struct {
		name    string
		verbs   []string
		wantErr bool
	}{
		{
			name:    "verb all",
			verbs:   []string{VerbAll},
			wantErr: false,
		},
		{
			name:    "read-only verbs",
			verbs:   []string{"get", "list"},
			wantErr: false,
		},
		{
			name:    "invalid verbs",
			verbs:   []string{"get", "put"},
			wantErr: true,
		},
		{
			name:    "explicit verbs",
			verbs:   []string{"get", "list", "create", "update", "delete"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateVerbs(tt.verbs); (err != nil) != tt.wantErr {
				t.Errorf("validateVerbs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_split(t *testing.T) {
	tests := []struct {
		name string
		list []string
		want []string
	}{
		{
			name: "single verb",
			list: []string{VerbAll},
			want: []string{VerbAll},
		},
		{
			name: "multiple verbs in single string",
			list: []string{"get,list,create"},
			want: []string{"get", "list", "create"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := split(tt.list); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitVerbs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateSubjects(t *testing.T) {
	tests := []struct {
		Name     string
		ExpErr   bool
		Subjects []Subject
	}{
		{
			Name: "valid",
			Subjects: []Subject{
				{
					Type: "user",
					Name: "eric",
				},
			},
		},
		{
			Name: "missing type",
			Subjects: []Subject{
				{
					Name: "eric",
				},
			},
			ExpErr: true,
		},
		{
			Name: "missing name",
			Subjects: []Subject{
				{
					Type: "user",
				},
			},
			ExpErr: true,
		},
		{
			Name: "invalid name",
			Subjects: []Subject{
				{
					Name: "^*^*#$^&#^",
					Type: "user",
				},
			},
			ExpErr: true,
		},
		{
			Name: "invalid type",
			Subjects: []Subject{
				{
					Name: "eric",
					Type: "#$*@$*@^#$*",
				},
			},
			ExpErr: true,
		},
		{
			Name: "one valid, one invalid",
			Subjects: []Subject{
				{
					Type: "user",
					Name: "eric",
				},
				{
					Type: "user",
				},
			},
			ExpErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name+"_ValidateSubjects", func(t *testing.T) {
			err := ValidateSubjects(test.Subjects)
			if test.ExpErr {
				if err == nil {
					t.Fatal("expected non-nil error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
			}
		})

		t.Run(test.Name+"_RoleBinding", func(t *testing.T) {
			crb := FixtureClusterRoleBinding("b")
			crb.Subjects = test.Subjects
			err := crb.Validate()
			if test.ExpErr {
				if err == nil {
					t.Fatal("expected non-nil error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
			}

		})

		t.Run(test.Name+"_ClusterRoleBinding", func(t *testing.T) {
			rb := FixtureRoleBinding("a", "b")
			rb.Subjects = test.Subjects
			err := rb.Validate()
			if test.ExpErr {
				if err == nil {
					t.Fatal("expected non-nil error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
			}

		})
	}
}

func TestClusterRoleBindingValidateSub(t *testing.T) {
	crb := FixtureClusterRoleBinding("a")
	if err := crb.Validate(); err != nil {
		t.Fatal(err)
	}
}
