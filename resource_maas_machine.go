package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"time"

	"github.com/juju/gomaasapi"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

// resourceMAASMachine creates a new terraform schema resource
func resourceMAASMachine() *schema.Resource {
	log.Println("[DEBUG] [resourceMAASMachine] Initializing data structure")
	return &schema.Resource{
		Create: resourceMAASMachineCreate,
		Read:   resourceMAASMachineRead,
		Update: resourceMAASMachineUpdate,
		Delete: resourceMAASMachineDelete,

		SchemaVersion: 1,

		Schema: map[string]*schema.Schema{
			"architecture": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"boot_type": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"cpu_count": {
				Type:     schema.TypeInt,
				Optional: true,
				ForceNew: true,
			},

			"disable_ipv4": {
				Type:     schema.TypeBool,
				Optional: true,
			},

			"distro_series": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"hostname": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"deploy": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			"deploy_hostname": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"original_hostname": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"sticky_hostname": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			"deploy_tags": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"deploy_interface": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
						},
						"type": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
							ValidateFunc: validation.StringInSlice([]string{
								"vlan",
								"physical",
								"bond",
							}, false),
						},
						"bond": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"parents": {
										Type:     schema.TypeList,
										Required: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"mode": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateFunc: validation.StringInSlice([]string{
											"balance-rr",
											"active-backup",
											"balance-xor",
											"broadcast",
											"802.3ad",
											"balance-tlb",
											"balance-alb",
										}, false),
										Default: "802.3ad",
									},
									"mii_mon": {
										Type:     schema.TypeInt,
										Optional: true,
										Default:  100,
									},
									"down_delay": {
										Type:         schema.TypeInt,
										Optional:     true,
										Default:      0,
										ValidateFunc: validation.IntAtLeast(0),
									},
									"up_delay": {
										Type:         schema.TypeInt,
										Optional:     true,
										Default:      0,
										ValidateFunc: validation.IntAtLeast(0),
									},
									"lacp_rate": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "slow",
										ValidateFunc: validation.StringInSlice([]string{
											"fast",
											"slow",
										}, false),
									},
									"xmit_hash_policy": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "layer2",
										ValidateFunc: validation.StringInSlice([]string{
											"layer2",
											"layer2+3",
											"layer3+4",
											"encap2+3",
											"encap3+4",
										}, false),
									},
									"num_grat_arp": {
										Type:         schema.TypeInt,
										Optional:     true,
										Default:      1,
										ValidateFunc: validation.IntAtLeast(0),
									},
								},
							},
						},
						"fabric": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
						"vlan": {
							Type:     schema.TypeInt,
							Optional: true,
							ForceNew: true,
						},
						"subnet": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							ValidateFunc: validation.CIDRNetwork(1, 32),
						},
						"ip_mode": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							Default:      "link_up",
							ValidateFunc: validation.StringInSlice([]string{"auto", "static", "dhcp", "link_up"}, false),
						},
						"ip": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							ValidateFunc: validation.SingleIP(),
						},
					},
				},
			},

			"tags": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"not_tags": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"release_erase": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: false,
				Default:  true,
			},

			"release_erase_secure": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: false,
				Default:  false,
			},

			"release_erase_quick": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: false,
				Default:  false,
			},

			"ip_addresses": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"macaddress_set": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"mac_address": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
						"resource_uri": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
					},
				},
			},

			"memory": {
				Type:     schema.TypeInt,
				Optional: true,
				ForceNew: true,
			},

			"netboot": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
			},

			"osystem": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"owner": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"physicalblockdevice_set": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"block_size": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"id": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"id_path": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"model": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"path": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"serial": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"size": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"tags": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},

			"power_state": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"power_type": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"pxe_mac": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"mac_address": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"resource_uri": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},

			"resource_uri": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"routers": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"status": {
				Type:     schema.TypeInt,
				Optional: true,
			},

			"volumes": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"label": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"size": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"tags": {
							Type:     schema.TypeList,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},

			"swap_size": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"system_id": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},

			"tag_names": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			"zone": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"not_in_zones"},
			},

			"not_in_zones": {
				Type:          schema.TypeList,
				Optional:      true,
				Elem:          &schema.Schema{Type: schema.TypeString},
				ConflictsWith: []string{"zone"},
			},

			"user_data": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				StateFunc: func(v interface{}) string {
					switch v.(type) {
					case string:
						hash := sha1.Sum([]byte(v.(string)))
						return hex.EncodeToString(hash[:])
					default:
						return ""
					}
				},
			},

			"hwe_kernel": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"comment": {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

// resourceMAASMachineCreate This function doesn't really *create* a new node but, power an already registered
func resourceMAASMachineCreate(d *schema.ResourceData, meta interface{}) error {
	log.Println("[DEBUG] [resourceMAASMachineCreate] Launching new maas_machine")

	/*
		According to the MAAS API documentation here: https://maas.ubuntu.com/docs/api.html
		We need to acquire or allocate a node before we start it.  We pass (as url.Values)
		some parameters that could be used to narrow down our selection (cpu_count, memory, etc.)
	*/

	controller := meta.(*Config).controller
	acquireParams := convertConstraints(d)

	var machine *gomaasapi.Machine
	m, _, err := controller.AllocateMachine(acquireParams)
	if err != nil {
		log.Println("[ERROR] [resourceMAASMachineCreate] Unable to allocate machine.")
		return err
	}
	machine = &m

	// set the node id
	d.SetId((*machine).SystemID())

	// save original hostname
	d.Set("original_hostname", (*machine).Hostname())

	// Update networking interfaces, if set
	if v, ok := d.GetOk("deploy_interface"); ok {

		// Need to loop through deploy_interface twice
		// first to look for bond type interfaces and create them
		// second loop link subnets, including bond interfaces that may have been created in the first loop
		//   The reason we do this is because the vlan interfaces may belong to the bond interface that has yet to be created

		// Loop for bond interfaces
		for _, nic := range v.(*schema.Set).List() {
			if err := doNIC(d, meta, "bond", nic.(map[string]interface{}), &machine); err != nil {
				log.Printf("[ERROR] Can't setup nic: %v", nic.(map[string]interface{}))
				if err := resourceMAASMachineDelete(d, meta); err != nil {
					log.Printf("[DEBUG] Unable to release node: %s", err.Error())
				}
				return err
			}
		}

		// Loop for vlan and physical interfaces
		for _, nic := range v.(*schema.Set).List() {
			if err := doNIC(d, meta, "", nic.(map[string]interface{}), &machine); err != nil {
				log.Printf("[ERROR] Can't setup nic: %v", nic.(map[string]interface{}))
				if err := resourceMAASMachineDelete(d, meta); err != nil {
					log.Printf("[DEBUG] Unable to release node: %s", err.Error())
				}
				return err
			}
		}
	}

	if d.Get("deploy").(bool) {
		// update machine attributes during allocated state
		params := url.Values{}
		if hostname, ok := d.GetOk("deploy_hostname"); ok {
			log.Printf("[DEBUG] Setting deploy hostname=%s", hostname.(string))
			params.Add("hostname", hostname.(string))
		}

		if len(params) > 0 {
			err = nodeUpdate(meta.(*Config).MAASObject, d.Id(), params)
			if err != nil {
				log.Println("[DEBUG] Unable to update node")
			}
		}
		if err := startMachine(d, meta, *machine); err != nil {
			// unable to perform action, release the node
			if err := resourceMAASMachineDelete(d, meta); err != nil {
				log.Printf("[DEBUG] Unable to release node: %s", err.Error())
			}
			return err
		}
		params = url.Values{}
		if !d.Get("sticky_hostname").(bool) {
			log.Printf("[DEBUG] reverting hostname to '%s'", d.Get("original_hostname").(string))
			params.Add("hostname", d.Get("original_hostname").(string))
		}

		if len(params) > 0 {
			err = nodeUpdate(meta.(*Config).MAASObject, d.Id(), params)
			if err != nil {
				log.Println("[DEBUG] Unable to update node")
			}
		}
	}
	// update node tags
	if tags, ok := d.GetOk("deploy_tags"); ok {
		for i := range tags.([]interface{}) {
			err := nodeTagsUpdate(meta.(*Config).MAASObject, d.Id(), tags.([]interface{})[i].(string))
			if err != nil {
				log.Printf("[ERROR] Unable to update node (%s) with tag (%s)", d.Id(), tags.([]interface{})[i].(string))
			}
		}
	}

	return resourceMAASMachineUpdate(d, meta)

}

// resourceMAASMachineRead read machine information from a maas node
func resourceMAASMachineRead(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG] Reading machine (%s) information.\n", d.Id())

	return nil
}

// resourceMAASMachineUpdate update machine in terraform state
func resourceMAASMachineUpdate(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG] [resourceMAASMachineUpdate] Modifying machine %s\n", d.Id())

	controller := meta.(*Config).controller
	var ids []string
	machines, err := controller.Machines(gomaasapi.MachinesArgs{
		SystemIDs: append(ids, d.Id()),
	})
	if err != nil {
		log.Printf("[ERROR] [resourceMAASMachineUpdate] cannnot list machines")
		return err
	}
	if len(machines) != 1 {
		return fmt.Errorf("[ERROR] [resourceMAASMachineUpdate] machine no longer exists")
	}
	d.Partial(true)

	if d.HasChange("deploy") {
		oraw, nraw := d.GetChange("deploy")
		newDeploy := nraw.(bool)
		oldDeploy := oraw.(bool)
		if newDeploy {
			switch machines[0].StatusName() {
			case "Allocated":
				// Start Deploy
				if err := startMachine(d, meta, machines[0]); err != nil {
					log.Printf("[WARN] Unable to start machine: %s", err.Error())
					if err := reAllocate(d, meta); err != nil {
						log.Printf("[ERROR] Unable to reallocate machine")
						return err
					}
					d.Set("deploy", oldDeploy)
					d.SetPartial("deploy")
				}

			case "Deployed":
				// This shouldn't happen
				log.Printf("[WARN] [resourceMAASMachineUpdate] unexpected Deployed state")
			}
		} else {
			switch machines[0].StatusName() {
			case "Allocated":
				// This shouldn't happen
				log.Printf("[WARN] [resourceMAASMachineUpdate] unexpected Deployed state")
			case "Deployed":
				// Release and then re-allocate, there is a tiny window chance where before re-allocating, the machine could have been acquired by someone else
				if err := reAllocate(d, meta); err != nil {
					d.Set("deploy", oldDeploy)
					d.SetPartial("deploy")
					return err
				}
			}
		}
	}

	d.Partial(false)

	log.Printf("[DEBUG] Done Modifying machine %s", d.Id())
	return resourceMAASMachineRead(d, meta)
}

// resourceMAASMachineDelete This function doesn't really *delete* a maas managed machine but releases (read, turns off) the node.
//     TODO: this should implement gomaasapi.Controller.ReleaseMachines, but currently ReleaseMachines doesn't support erase release
func resourceMAASMachineDelete(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG] Deleting machine %s\n", d.Id())

	controller := meta.(*Config).controller
	var ids []string
	machines, err := controller.Machines(gomaasapi.MachinesArgs{
		SystemIDs: append(ids, d.Id()),
	})
	if err != nil {
		log.Printf("[ERROR] [resourceMAASMachineDelete] cannnot list machines")
		return err
	}
	if len(machines) != 1 {
		return fmt.Errorf("[ERROR] [resourceMAASMachineDelete] machine no longer exists")
	}
	machine := machines[0]

	release_params := url.Values{}

	if release_erase, ok := d.GetOk("release_erase"); ok {
		release_params.Add("erase", strconv.FormatBool(release_erase.(bool)))
	}

	if release_erase_secure, ok := d.GetOk("release_erase_secure"); ok {
		// setting erase to true in the event a user didn't set both options
		release_params.Add("erase", strconv.FormatBool(true))
		release_params.Add("secure_erase", strconv.FormatBool(release_erase_secure.(bool)))
	}

	if release_erase_quick, ok := d.GetOk("release_erase_quick"); ok {
		// setting erase to true in the event a user didn't set both options
		release_params.Add("erase", strconv.FormatBool(true))
		release_params.Add("quick_erase", strconv.FormatBool(release_erase_quick.(bool)))
	}

	// First check status of machine:
	//  If it's Deployed then Release, Acquire

	alreadyErased := false
	if machine.StatusName() == "Deployed" {

		// RELEASE
		if err := nodeRelease(d, meta, release_params); err != nil {
			return err
		}
		alreadyErased = true

		// ACQUIRE - quickly before someone else acquires
		//       see issue https://bugs.launchpad.net/maas/+bug/1815777
		var err error
		machine, _, err = controller.AllocateMachine(gomaasapi.AllocateMachineArgs{
			SystemId: d.Id(),
		})
		if err != nil {
			log.Printf("[ERROR] Unable to reallocate machine(%s) did someone already acquire it?!", d.Id())
			return err
		}
	}
	//  proceed to restore config and finally release
	//

	if v, ok := d.GetOk("deploy_interface"); ok {
		//Disconnect or delete any interfaces
		nicMap := make(map[string]gomaasapi.Interface, 0)
		for _, nic := range machine.InterfaceSet() {
			nicMap[nic.Name()] = nic
		}
		for _, netInterfaces := range v.(*schema.Set).List() {
			i := netInterfaces.(map[string]interface{})

			// if interface is physical, then we disconnect
			// otherwise we delete the interface
			if nic, ok := nicMap[i["name"].(string)]; ok && nic.Type() == "physical" {
				if err := nic.Disconnect(); err != nil {
					log.Println("[ERROR] [resourceMAASMachineDelete] Unable to disconnect interface %s", nic.Name())
					return err
				}
			} else {
				// don't care if we can delete it or not, since it's possible a bond interface was deleted earlier in the loop
				// which would automatically delete any children interfaces and thus cause subsequent delete attempts to fail later in the loop
				nic.Disconnect()
				nic.Delete()
			}
		}
	}

	// remove deploy hostname if set
	if _, ok := d.GetOk("deploy_hostname"); ok {
		params := url.Values{}
		params.Set("hostname", d.Get("original_hostname").(string))
		err := nodeUpdate(meta.(*Config).MAASObject, d.Id(), params)
		if err != nil {
			log.Println("[DEBUG] Unable to reset hostname: %s", err)
		}
	}

	// remove deployed tags
	if tags, ok := d.GetOk("deploy_tags"); ok {
		for i := range tags.([]interface{}) {
			err := nodeTagsRemove(meta.(*Config).MAASObject, d.Id(), tags.([]interface{})[i].(string))
			if err != nil {
				log.Printf("[ERROR] Unable to update node (%s) with tag (%s)", d.Id(), tags.([]interface{})[i].(string))
			}
		}
	}

	if alreadyErased {
		release_params = url.Values{}
	}
	if err := nodeRelease(d, meta, release_params); err != nil {
		return err
	}

	log.Printf("[DEBUG] [resourceMAASMachineDelete] Node (%s) released", d.Id())

	d.SetId("")

	return nil
}

func convertConstraints(d *schema.ResourceData) gomaasapi.AllocateMachineArgs {
	args := gomaasapi.AllocateMachineArgs{}

	if hostname, ok := d.GetOk("hostname"); ok {
		args.Hostname = hostname.(string)
	}

	if systemID, ok := d.GetOk("system_id"); ok {
		args.SystemId = systemID.(string)
	}

	if architecture, ok := d.GetOk("architecture"); ok {
		args.Architecture = architecture.(string)
	}

	if minCPUCount, ok := d.GetOk("cpu_count"); ok {
		args.MinCPUCount = minCPUCount.(int)
	}

	if minRAM, ok := d.GetOk("memory"); ok {
		args.MinMemory = minRAM.(int)
	}

	if tags, ok := d.GetOk("tags"); ok {
		args.Tags = expandStringList(tags.([]interface{}))
	}

	if notTags, ok := d.GetOk("not_tags"); ok {
		args.NotTags = expandStringList(notTags.([]interface{}))
	}

	if zone, ok := d.GetOk("zone"); ok {
		args.Zone = zone.(string)
	}

	if notInZones, ok := d.GetOk("not_in_zones"); ok {
		args.NotInZone = expandStringList(notInZones.([]interface{}))
	}

	volumes := d.Get("volumes").(*schema.Set).List()

	for _, vol := range volumes {
		v := vol.(map[string]interface{})
		args.Storage = append(args.Storage, gomaasapi.StorageSpec{
			Label: v["label"].(string),
			Size:  v["size"].(int),
			Tags:  v["tags"].([]string),
		})
	}

	if comment, ok := d.GetOk("comment"); ok {
		args.Comment = comment.(string)
	}

	return args
}

func getSubnets(controller *gomaasapi.Controller) (map[string]gomaasapi.Subnet, error) {
	// Get all the spaces
	spaces, err := (*controller).Spaces()
	if err != nil {
		return nil, err
	}

	// Get all the subnets, they have unique CIDRs across Spaces
	subnets := make(map[string]gomaasapi.Subnet, 0)
	for _, space := range spaces {
		for _, subnet := range space.Subnets() {
			log.Printf("[DEBUG] spaceID=%d, spaceName=%s, subnetID=%d, subnetName=%s", space.ID(), space.Name(), subnet.ID(), subnet.Name())
			subnets[subnet.CIDR()] = subnet
		}
	}

	return subnets, nil
}

func reAllocate(d *schema.ResourceData, meta interface{}) error {
	controller := meta.(*Config).controller

	// Release
	if err := controller.ReleaseMachines(gomaasapi.ReleaseMachinesArgs{
		SystemIDs: []string{d.Id()},
	}); err != nil {
		return err
	}

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"Deployed", "Releasing"},
		Target:     []string{"Ready"},
		Refresh:    getNodeStatus(meta.(*Config).MAASObject, d.Id()),
		Timeout:    30 * time.Minute,
		Delay:      10 * time.Second,
		MinTimeout: 3 * time.Second,
	}

	if _, err := stateConf.WaitForState(); err != nil {
		return fmt.Errorf(
			"[ERROR] [resourceMAASMachineUpdate] Error waiting for machine (%s) to become ready: %s", d.Id(), err)
	}

	// Acquire (quickly before someone else takes it!!!)
	_, _, err := controller.AllocateMachine(gomaasapi.AllocateMachineArgs{
		SystemId: d.Id(),
	})
	if err != nil {
		log.Println("[ERROR] [resourceMAASMachineUpdate] Unable to allocate machine.")
		return err
	}
	return nil
}

func startMachine(d *schema.ResourceData, meta interface{}, machine gomaasapi.Machine) error {
	startArgs := gomaasapi.StartArgs{
		UserData:     base64encode(d.Get("user_data").(string)),
		DistroSeries: d.Get("distro_series").(string),
		Kernel:       d.Get("hwe_kernel").(string),
		Comment:      d.Get("comment").(string),
	}

	if err := machine.Start(startArgs); err != nil {
		log.Printf("[ERROR] [resourceMAASMachineUpdate] Unable to power up node: %s\n", d.Id())
		return err
	}

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"Deploying", "Releasing"},
		Target:     []string{"Deployed"},
		Refresh:    getNodeStatus(meta.(*Config).MAASObject, d.Id()),
		Timeout:    25 * time.Minute,
		Delay:      10 * time.Second,
		MinTimeout: 3 * time.Second,
	}

	if _, err := stateConf.WaitForState(); err != nil {
		return fmt.Errorf("[ERROR] [resourceMAASMachineUpdate] Error waiting for machine (%s) to become deployed: %s", d.Id(), err)
	}
	return nil
}

func readMachine(d *schema.ResourceData, meta interface{}) (*gomaasapi.Machine, error) {

	controller := meta.(*Config).controller
	var ids []string

	machines, err := controller.Machines(gomaasapi.MachinesArgs{
		SystemIDs: append(ids, d.Id()),
	})
	if err != nil {
		log.Printf("[ERROR] [resourceMAASMachineCreate] cannnot list machines")
		if err := resourceMAASMachineDelete(d, meta); err != nil {
			log.Printf("[DEBUG] Unable to release node: %s", err.Error())
		}
		return nil, err
	}
	if len(machines) != 1 {
		if err := resourceMAASMachineDelete(d, meta); err != nil {
			log.Printf("[DEBUG] Unable to release node: %s", err.Error())
		}
		return nil, fmt.Errorf("[ERROR] [resourceMAASMachineCreate] machine ID(%s) is not unique", machines[0].SystemID())
	}
	// refresh since we just created a bond

	return &machines[0], nil
}

func doNIC(d *schema.ResourceData, meta interface{}, nicWant string, i map[string]interface{}, machine **gomaasapi.Machine) error {

	nicType := "vlan"
	if t, ok := i["type"].(string); ok {
		nicType = t
	}

	// if the type doesn't match nicType then exit normally
	if (nicWant == "bond" && nicType != "bond") || (nicWant != "bond" && nicType == "bond") {
		return nil
	}

	controller := meta.(*Config).controller

	nicsMap := make(map[string]int, len((**machine).InterfaceSet()))
	for _, nic := range (**machine).InterfaceSet() {
		nicsMap[nic.Name()] = nic.ID()
	}
	fabrics, err := controller.Fabrics()
	if err != nil {
		log.Println("[ERROR] Unable to get fabrics")
		if err := resourceMAASMachineDelete(d, meta); err != nil {
			log.Printf("[DEBUG] Unable to release node: %s", err.Error())
		}
		return err
	}
	fabricsMap := make(map[string]*gomaasapi.Fabric, len(fabrics))
	for _, fabric := range fabrics {
		fabricsMap[fabric.Name()] = &fabric
	}

	subnets, err := getSubnets(&controller)

	// Create bond interface if necessary
	if b, ok := i["bond"]; ok && nicType == "bond" && len(b.(*schema.Set).List()) > 0 {
		if _, bondAlreadyExists := nicsMap[i["name"].(string)]; !bondAlreadyExists {
			bondParams := b.(*schema.Set).List()[0].(map[string]interface{})
			parentNics, ok := bondParams["parents"].([]interface{})
			if !ok || parentNics == nil || len(parentNics) == 0 {
				if err := resourceMAASMachineDelete(d, meta); err != nil {
					log.Printf("[DEBUG] Unable to release node: %s", err.Error())
				}
				return fmt.Errorf("[ERROR] bond parents missing")
			}
			var parentIDs []int
			for _, p := range parentNics {
				if pID, ok := nicsMap[p.(string)]; ok && pID > 0 {
					parentIDs = append(parentIDs, pID)
				} else {
					if err := resourceMAASMachineDelete(d, meta); err != nil {
						log.Printf("[DEBUG] Unable to release node: %s", err.Error())
					}
					return fmt.Errorf("[ERROR] non existing parent interface: %s", p)
				}
			}
			nic, err := (**machine).CreateBondInterface(gomaasapi.CreateBondInterfaceArgs{
				Name:    i["name"].(string),
				Parents: parentIDs,
			})
			if err != nil {
				log.Printf("[ERROR] Unable to create bond")
				if err := resourceMAASMachineDelete(d, meta); err != nil {
					log.Printf("[DEBUG] Unable to release node: %s", err.Error())
				}
				return err
			}

			// refresh machine to relect the newly created interface
			if *machine, err = readMachine(d, meta); err != nil {
				log.Printf("[ERROR] Unable to read machine %d", d.Id())
				if err := resourceMAASMachineDelete(d, meta); err != nil {
					log.Printf("[ERROR] Unable to release node: %s", err.Error())
				}
				return err
			}

			nicsMap[i["name"].(string)] = nic.ID()
		}
	}

	// Find the matching interface
	if nicID, ok := nicsMap[i["name"].(string)]; ok && nicID > 0 {

		// Found the interface, now to configure it
		nic := (**machine).Interface(nicID)

		if fabricName, ok := i["fabric"].(string); ok && fabricName != "" {
			fabric, ok := fabricsMap[fabricName]
			if !ok {
				if err := resourceMAASMachineDelete(d, meta); err != nil {
					log.Printf("[DEBUG] Unable to release node: %s", err.Error())
				}
				return fmt.Errorf("[ERROR] fabric doesn't exist")
			}
			// We connect the fabric to this interface by associating the untagged vlan (vid = 0)
			vid := 0
			if v, ok := i["vlan"].(int); ok {
				if t, ok := i["type"].(string); ok && t == "physical" {
					vid = v
				}
			}
			vlans := (*fabric).VLANs()
			for _, v := range vlans {
				if v.VID() == vid {
					if err := nic.Update(gomaasapi.UpdateInterfaceArgs{
						VLAN: v,
					}); err != nil {
						log.Printf("[ERROR] Cannot update nic %s", nic.Name())
						if err := resourceMAASMachineDelete(d, meta); err != nil {
							log.Printf("[DEBUG] Unable to release node: %s", err.Error())
						}
						return err
					}
				}
			}
			// figure out the VLAN to configure

			// default to untagged (vid=0) vlan
			vIndex := -1
			for i, v := range vlans {
				if v.VID() == 0 {
					vIndex = i
					break
				}
			}

			if vlanNum, ok := i["vlan"].(int); ok && nicType == "vlan" {
				vlanExists := false
				for i, v := range vlans {
					if v.VID() == vlanNum {
						vlanExists = true
						vIndex = i
						break
					}
				}
				if !vlanExists {
					if err := resourceMAASMachineDelete(d, meta); err != nil {
						log.Printf("[DEBUG] Unable to release node: %s", err.Error())
					}
					return fmt.Errorf("[ERROR] vlan doesn't exist")
				}
			}

			// If interface is a vlan interface then obtain a pointer to its Interface object, create if necessary
			nicName := i["name"].(string)
			if nicType == "vlan" {
				nicName = nicName + "." + strconv.Itoa(vlans[vIndex].VID())
				if existingNIC, ok := nicsMap[nicName]; ok {
					log.Printf("[DEBUG] VLAN interface (%s) already exists, no need to create", nicName)
					nic = (**machine).Interface(existingNIC)
				} else {
					log.Printf("[DEBUG] Creating VLAN interface with vid=%d", vlans[vIndex].VID())
					nicVLAN, err := nic.CreateVLANInterface(gomaasapi.CreateVLANInterfaceArgs{
						VLAN: vlans[vIndex],
					})

					if err != nil {
						log.Printf("[ERROR] Failed creating VLAN interface with vid=%d", vlans[vIndex].VID())
						if err := resourceMAASMachineDelete(d, meta); err != nil {
							log.Printf("[DEBUG] Unable to release node: %s", err.Error())
						}
						return err
					}
					nic = nicVLAN
				}
			}

			// Set subnet if set
			if cidr, ok := i["subnet"].(string); ok && cidr != "" {
				if subnet, ok := subnets[cidr]; ok {
					log.Printf("[INFO] link subnet ID=%d CIDR=%s to nicID=%d IP=%s", subnet.ID(), cidr, nic.ID(), i["ip"].(string))

					err := nic.LinkSubnet(gomaasapi.LinkSubnetArgs{
						Mode:      getIPMode(i["ip_mode"].(string)),
						Subnet:    subnet,
						IPAddress: i["ip"].(string),
					})
					if err != nil {
						log.Printf("[ERROR]  Unable to link subnet ID=%d CIDR=%s to nicID=%d IP=%s", subnet.ID(), cidr, nic.ID(), i["ip"].(string))
						if err := resourceMAASMachineDelete(d, meta); err != nil {
							log.Printf("[DEBUG] Unable to release node: %s", err.Error())
						}
						return err
					}
				} else {
					if err := resourceMAASMachineDelete(d, meta); err != nil {
						log.Printf("[DEBUG] Unable to release node: %s", err.Error())
					}
					return fmt.Errorf("[ERROR] subnet (%s) does not exist", cidr)
				}
			}
		}

	} else {
		if err := resourceMAASMachineDelete(d, meta); err != nil {
			log.Printf("[DEBUG] Unable to release node: %s", err.Error())
		}
		return fmt.Errorf("[ERROR] [resourceMAASMachineCreate] cannot find interface name: %s in map: %v", i["name"].(string), nicsMap)
	}
	return nil
}

func getIPMode(s string) (ipMode gomaasapi.InterfaceLinkMode) {

	switch s {
	case "static", "auto":
		ipMode = gomaasapi.LinkModeStatic
	case "dhcp":
		ipMode = gomaasapi.LinkModeDHCP
	default:
		ipMode = gomaasapi.LinkModeLinkUp
	}

	return ipMode
}
