package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Bakemono-san/gofsen"
	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/go-utils/utils/slice"
	"github.com/peter2121/ldap-mcli/ldap"
)

type LdapDataHandler struct {
	LdapConfig *ldap.Config
	LdapClient *ldap.Client
}

func NewLdapDataHandler(config *ldap.Config, opts ...ldap.ClientOption) *LdapDataHandler {
	ldap_data_handler := LdapDataHandler{}
	ldap_data_handler.LdapConfig = config
	ldap_data_handler.LdapClient = ldap.NewClient(config, opts...)
	if ldap_data_handler.LdapClient != nil {
		return &ldap_data_handler
	} else {
		return nil
	}
}

func (ldh *LdapDataHandler) UsersHandler(c *gofsen.Context) {
	users, _ := ldh.LdapClient.Users.GetAll()
	c.JSON(users)
}

func (ldh *LdapDataHandler) UserHandler(c *gofsen.Context) {
	var user, user_old *ldap.User = nil, nil
	var err *errors.Error
	uid := c.Param("uid")
	srch_by_mail := strings.Contains(uid, "@")
	switch c.Request.Method {
	case "GET":
		if srch_by_mail {
			user, err = ldh.LdapClient.Users.GetByEmail(uid)
		} else {
			user, err = ldh.LdapClient.Users.GetByUid(uid)
		}
		if err == nil {
			if user != nil {
				c.JSON(user)
			}
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  err.Message,
			})
		}
	case "PUT":
		if srch_by_mail {
			user_old, err = ldh.LdapClient.Users.GetByEmail(uid)
		} else {
			user_old, err = ldh.LdapClient.Users.GetByUid(uid)
		}
		// TODO: manage user creation if user is not found
		if err != nil {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  err.Message,
			})
		}
		if user_old == nil {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Cannot find existing user to modify",
			})
		}
		if err := c.BindJSON(&user); err != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Invalid JSON",
			})
			return
		}
		errmod := ldh.LdapClient.Users.ModifyUser(*user, *user_old)
		if errmod != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errmod.Message,
			})
			return
		}
		user_mod, errum := ldh.LdapClient.Users.GetByEmail(user.Mail)
		if (errum == nil) && (user_mod != nil) {
			c.JSON(user_mod)
			return
		} else if errum != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errum.Message,
			})
			return
		} else {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Cannot get modified user from LDAP",
			})
			return
		}
	case "DELETE":
		if srch_by_mail {
			err = ldh.LdapClient.Users.DeleteByEmail(uid)
		} else {
			err = ldh.LdapClient.Users.DeleteByUid(uid)
		}
		if err == nil {
			c.Status(204)
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  err.Message,
			})
		}
	}

}

func (ldh *LdapDataHandler) CreateUserHandler(c *gofsen.Context) {
	var user ldap.User
	if err := c.BindJSON(&user); err != nil {
		c.Status(400).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "Invalid JSON",
		})
		return
	}
	errc := ldh.LdapClient.Users.Create(user)
	if errc == nil {
		c.Status(201).JSON(user)
	} else {
		c.JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  errc.Message,
		})
	}
}

func (ldh *LdapDataHandler) GroupsHandler(c *gofsen.Context) {
	var have_gss bool = false
	var have_gsm bool = false

	groupss, _ := ldh.LdapClient.GroupsSec.GetAll()
	if len(groupss) > 0 {
		have_gss = true
	}
	/*
		for _, group := range groupss {
			fmt.Printf("Security Group: %s\n", group.Cn)
		}
	*/
	groupsm, _ := ldh.LdapClient.GroupsMail.GetAll()
	if len(groupsm) > 0 {
		have_gsm = true
	}
	/*
		for _, group := range groupsm {
			fmt.Printf("Distribution Group: %s (%s)\n", group.Cn, group.Mail)
		}
	*/
	var str_gss string = ""
	var str_gsm string = ""

	if have_gss {
		byte_gss, err_gss := json.Marshal(groupss)
		if err_gss == nil {
			str_gss = strings.Trim(string(byte_gss), "[]")
		}
	}

	if have_gsm {
		byte_gsm, err_gsm := json.Marshal(groupsm)
		if err_gsm == nil {
			str_gsm = strings.Trim(string(byte_gsm), "[]")
		}
	}

	var result string = "[ "
	if len(str_gss) > 0 {
		result = result + str_gss
		if len(str_gsm) > 0 {
			result = result + ", " + str_gsm
		}
	} else {
		result = result + str_gsm
	}
	result = result + " ]"

	var jres []map[string]any
	erruj := json.Unmarshal([]byte(result), &jres)
	if erruj == nil {
		c.JSON(jres)
	} else {
		fmt.Printf("Error unmarshaling concatenated result: %v\n", erruj)
	}
}

func (ldh *LdapDataHandler) GroupHandler(c *gofsen.Context) {
	gid := c.Param("gid")
	srch_by_mail := strings.Contains(gid, "@")

	var group_mail *ldap.GroupMail = nil
	var errgm *errors.Error = nil
	switch c.Request.Method {
	case "GET":
		if !srch_by_mail {
			group_sec, errgs := ldh.LdapClient.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
			if (errgs == nil) && (group_sec != nil) {
				c.JSON(group_sec)
				return
			}
		}
		if srch_by_mail {
			group_mail, errgm = ldh.LdapClient.GroupsMail.GetOne(ldap.MailAttr, gid, "")
		} else {
			group_mail, errgm = ldh.LdapClient.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
		}
		if errgm == nil {
			if group_mail != nil {
				c.JSON(group_mail)
			}
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errgm.Message,
			})
		}
	case "PUT":
		var group_sec *ldap.GroupSec = nil
		if !srch_by_mail {
			group_old, errgs := ldh.LdapClient.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
			if (errgs == nil) && (group_old != nil) {
				if err := c.BindJSON(&group_sec); err != nil {
					c.Status(400).JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  "Invalid JSON",
					})
					return
				}
				errmod := ldh.LdapClient.GroupsSec.ModifyGroup(*group_sec, *group_old)
				if errmod != nil {
					c.Status(400).JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  errmod.Message,
					})
					return
				}
				group_mod, errgsm := ldh.LdapClient.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
				if (errgsm == nil) && (group_mod != nil) {
					c.JSON(group_mod)
					return
				} else if errgsm != nil {
					c.Status(400).JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  errgsm.Message,
					})
					return
				} else {
					c.Status(400).JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  "Cannot get modified group from LDAP",
					})
					return
				}
			} else {
				group_old, errgs := ldh.LdapClient.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
				if (errgs == nil) && (group_old != nil) {
					if err := c.BindJSON(&group_mail); err != nil {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "Invalid JSON",
						})
						return
					}
					errmod := ldh.LdapClient.GroupsMail.ModifyGroup(*group_mail, *group_old)
					if errmod != nil {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  errmod.Message,
						})
						return
					}
					group_mod, errgsm := ldh.LdapClient.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
					if (errgsm == nil) && (group_mod != nil) {
						c.JSON(group_mod)
						return
					} else if errgsm != nil {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  errgsm.Message,
						})
						return
					} else {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "Cannot get modified group from LDAP",
						})
						return
					}
				} else {
					// Not found, need to be created
					var base_group ldap.BaseGroup
					body_bytes, err := io.ReadAll(c.Request.Body)
					if (err != nil) || (len(body_bytes) == 0) {
						c.Status(500).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "FATAL: cannot read request body",
						})
						return
					}
					if err := json.Unmarshal(body_bytes, &base_group); err != nil {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "Invalid JSON: cannot be parsed to BaseGroup",
						})
						return
					}
					group_type := base_group.Type
					if !slice.EntryExists(ldap.GROUP_TYPES, group_type) {
						c.Status(400).JSON(map[string]any{
							"api":    "v1",
							"status": "error",
							"error":  "Invalid JSON: invalid group type",
						})
						return
					}
					ldh.CreateGroup(c, body_bytes, group_type)
				}
			}
		}
	case "DELETE":
		var errdel *errors.Error = nil
		if srch_by_mail {
			group_mail, errgm = ldh.LdapClient.GroupsMail.GetOne(ldap.MailAttr, gid, "")
			if (errgm == nil) && (group_mail != nil) {
				errdel = ldh.LdapClient.GroupsMail.Delete(group_mail.Cn, "")
				if errdel != nil {
					c.JSON(map[string]any{
						"api":    "v1",
						"status": "error",
						"error":  errdel.Message,
					})
				} else {
					c.Status(204)
				}
			} else {
				c.JSON(map[string]any{
					"api":    "v1",
					"status": "error",
					"error":  errgm.Message,
				})
			}
		} else {
			var errfin string
			gm, errgm := ldh.LdapClient.GroupsMail.GetOne(ldap.CommonNameAttr, gid, "")
			if (errgm == nil) && (gm != nil) {
				errdel = ldh.LdapClient.GroupsMail.Delete(gm.Cn, "")
				if errdel == nil {
					c.Status(204)
				}
			}
			gs, errgs := ldh.LdapClient.GroupsSec.GetOne(ldap.CommonNameAttr, gid, "")
			if (errgs == nil) && (gs != nil) {
				errdel = ldh.LdapClient.GroupsMail.Delete(gs.Cn, gs.Ou)
				if errdel == nil {
					c.Status(204)
				}
			}
			if errgm != nil {
				errfin = fmt.Sprintf("Error searching for Mail List Group %s=%s: %s", ldap.CommonNameAttr, gid, errgm.Message)
			}
			if errgs != nil {
				errfin = fmt.Sprintf("%s Error searching for Security Group %s=%s: %s", errfin, ldap.CommonNameAttr, gid, errgs.Message)
			}
			if errdel != nil {
				errfin = fmt.Sprintf("%s Error deleting Group %s=%s: %s", errfin, ldap.CommonNameAttr, gid, errdel.Message)
			}
			if errfin != "" {
				c.JSON(map[string]any{
					"api":    "v1",
					"status": "error",
					"error":  errfin,
				})
			}
		}
	}
}

func (ldh *LdapDataHandler) CreateGroupHandler(c *gofsen.Context) {
	var base_group ldap.BaseGroup
	body_bytes, err := io.ReadAll(c.Request.Body)
	if (err != nil) || (len(body_bytes) == 0) {
		c.Status(500).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "FATAL: cannot read request body",
		})
		return
	}
	if err := json.Unmarshal(body_bytes, &base_group); err != nil {
		c.Status(400).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "Invalid JSON: cannot be parsed to BaseGroup",
		})
		return
	}
	group_type := base_group.Type
	if !slice.EntryExists(ldap.GROUP_TYPES, group_type) {
		c.Status(400).JSON(map[string]any{
			"api":    "v1",
			"status": "error",
			"error":  "Invalid JSON: invalid group type",
		})
		return
	}
	ldh.CreateGroup(c, body_bytes, group_type)
}

func (ldh *LdapDataHandler) CreateGroup(c *gofsen.Context, body_bytes []byte, group_type string) {
	switch group_type {
	case ldap.GROUP_TYPES[0]: // "Mail"
		var group ldap.GroupMail
		if err := json.Unmarshal(body_bytes, &group); err != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Invalid JSON: cannot be parsed to GroupMail",
			})
			return
		}
		errc := ldh.LdapClient.GroupsMail.CreateGroup(group)
		if errc == nil {
			c.Status(201).JSON(group)
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errc.Message,
			})
		}
	case ldap.GROUP_TYPES[1]: // "Security"
		var group ldap.GroupSec
		if err := json.Unmarshal(body_bytes, &group); err != nil {
			c.Status(400).JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  "Invalid JSON: cannot be parsed to GroupSec",
			})
			return
		}
		errc := ldh.LdapClient.GroupsSec.CreateGroup(group)
		if errc == nil {
			c.Status(201).JSON(group)
		} else {
			c.JSON(map[string]any{
				"api":    "v1",
				"status": "error",
				"error":  errc.Message,
			})
		}
	}
}
