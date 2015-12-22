``<?php
	/**
	 * @package ubnt
	 * @subpackage views
	 * @copyright 2012 Ubiquiti Networks, Inc. All rights reserved.
	 */
?>

<!-- Start: Services -->
<div id="Services" class="main-section">
	<div class="section-tabs">
		<ul>
			<li><a href="#Services/DHCP" data-container="ServicesDhcp">DHCP Server</a></li>
			<li><a href="#Services/DNS" data-container="ServicesDns">DNS</a></li>
			<li><a href="#Services/Blacklist" data-container="ServicesBlacklist">Blacklist</a></li>
			<li><a href="#Services/PPPoE" data-container="ServicesPppoe">PPPoE</a></li>

			<?php /*
			<li><a href="#Services/SMNP" data-container="ServicesSmnp">SMNP</a></li>
			<li><a href="#Services/WebProxy" data-container="ServicesWebProxy">WebProxy Cache</a></li>
			*/ ?>
		</ul>
	</div>
	<div class="section-container tall tabbed">
		<div id="ServicesDhcp" class="wide tall">
			<div id="ServicesDhcpAdd" class="add"></div>
			<?php /*
			<div id="ServicesDhcpFilters" class="filters shared">
				<ul class="ui-tabs-buttonset">
					<li class="dhcp-server"><a href="#Services/DHCP/Server" data-container="ServicesDhcpServer">DHCP Server</a></li>
					<li class="dhcp-relay"><a href="#Services/DHCP/Relay" data-container="ServicesDhcpRelay">DHCP Relay</a></li>
					<li class="dhcpv6-server"><a href="#Services/DHCP/v6/Server" data-container="ServicesDhcp6Server">DHCPv6 Server</a></li>
					<li class="dhcpv6-relay"><a href="#Services/DHCP/v6/Relay" data-container="ServicesDhcp6Relay">DHCPv6 Relay</a></li>
				</ul>
			</div>
			*/ ?>

			<div id="ServicesDhcpServer" class="wide tall"></div>
			<?php /*
			<div id="ServicesDhcpRelay" class="wide tall"></div>
			<div id="ServicesDhcp6Server" class="wide tall"></div>
			<div id="ServicesDhcp6Relay" class="wide tall"></div>
			*/ ?>
		</div>
		<div id="ServicesDns" class="wide tall"></div>
		<div id="ServicesBlacklist" class="wide tall"></div>
		<div id="ServicesPppoe" class="wide tall"></div>

		<?php /*
		<div id="ServicesVrrp" class="wide tall"></div>
		<div id="ServicesWebProxy" class="wide tall"></div>
		*/ ?>
	</div>
</div>

<script id="ServicesDhcpServerTemplate" type="text/template">
	<div class="section-container table-container">
		<div id="ServicesDhcpServerAdd" class="add">
			<button type="button">Add DHCP Server</button>
		</div>
		<%= filters %>
		<table class="data-table">
			<thead>
				<tr>
					<th>Name</th>
					<th>Subnet</th>
					<th>Pool size</th>
					<th>Leased</th>
					<th>Available</th>
					<th>Static</th>
					<th>&nbsp;</th>
				</tr>
			</thead>
			<tbody></tbody>
		</table>
	</div>
</script>

<script id="ServicesDhcpServerCreateTemplate" type="text/template">
	<form method="post" class="ui-form">
		<div class="scrollable">
			<div class="tab-content unpadded info">
				<div class="section form">
					<fieldset class="primary">
						<label class="primary required" for="name<%= id %>">DHCP Name</label>
						<div>
							<input type="text" id="name<%= id %>" name="name" class="text-input" data-infotip="Unique name for this DHCP server"/>
						</div>

						<label class="primary required" for="subnet<%= id %>">Subnet</label>
						<div>
							<input type="text" id="subnet<%= id %>" name="subnet" class="text-input" data-infotip="IPv4 subnet.  Must be a subnet configured on some interface.</br></br>Example <b>192.0.2.0/24</b>"/>
						</div>

						<label class="primary" for="range-start<%= id %>">Range Start</label>
						<div>
							<input type="text" id="range-start<%= id %>" name="range-start" class="text-input" data-infotip="Begining IPv4 address in subnet to be allocated. If no start/stop range is used then all allocations must be static-mapped"/>
						</div>

						<label class="primary" for="range-stop<%= id %>">Range Stop</label>
						<div>
							<input type="text" id="range-stop<%= id %>" name="range-stop" class="text-input" data-infotip="Last IPv4 address in subnet to be allocated. If no start/stop range is used then all allocations must be static-mapped"/>
						</div>

						<label class="primary" for="router<%= id %>">Router</label>
						<div>
							<input type="text" id="router<%= id %>" name="router" class="text-input" />
						</div>

						<label class="primary" for="dns1<%= id %>">DNS 1</label>
						<div>
							<input type="text" id="dns1<%= id %>" name="dns1" class="text-input" />
						</div>

						<label class="primary" for="dns2<%= id %>">DNS 2</label>
						<div>
							<input type="text" id="dns2<%= id %>" name="dns2" class="text-input" />
						</div>

						<label class="primary" for="unifi-controller<%= id %>">Unifi Controller</label>
						<div>
							<input type="text" id="unifi-controller<%= id %>" name="unifi-controller" class="text-input" data-infotip="IP address of UniFi controller" />
						</div>

						<label class="primary" for="enabled<%= id %>">Enable</label>
						<div>
							<input type="checkbox" id="enabled<%= id %>" name="enabled" value="1" class="check-box-input" checked="true" />
						</div>
					</fieldset>

					<fieldset class="actions">
						<button type="submit">Save</button>
					</fieldset>
				</div>
			</div>
		</div>
	</form>
</script>

<script id="ServicesDhcpServerConfigTemplate" type="text/template">
	<form method="post" class="ui-form">
		<div class="dialog-tabs">
			<ul>
				<li class="leases"><a href="#leases">Leases</a></li>
				<li class="mappings"><a href="#mappings" data-button="create">Static MAC/IP Mapping</a></li>
				<li class="details"><a href="#details">Details</a></li>
			</ul>
		</div>
        <div class="dialog-stats">
            <div class="boxed">
                <dl class="counts first">
                    <dt>Pool Size:</dt>
                    <dd class="pool-size"></dd>
                </dl>

                <dl class="counts middle">
                    <dt>Leased:</dt>
                    <dd class="leased"></dd>
                </dl>

                <dl class="counts middle">
                    <dt>Available:</dt>
                    <dd class="available"></dd>
                </dl>

                <dl class="counts last">
                    <dt>Static:</dt>
                    <dd class="static"></dd>
                </dl>
            </div>

            <dl class="plain">
                <dt>Subnet:</dt>
                <dd class="subnet"></dd>

                <dt>Range Start:</dt>
                <dd class="range-start"></dd>

                <dt>Range End:</dt>
                <dd class="range-end"></dd>

                <dt>Unifi Controller:</dt>
                <dd class="unifi-controller"></dd>
            </dl>

            <dl class="plain">
                <dt>Router:</dt>
                <dd class="router"></dd>

                <dt>DNS 1:</dt>
                <dd class="dns1"></dd>

                <dt>DNS 2:</dt>
                <dd class="dns2"></dd>

                <dt>Status:</dt>
                <dd class="status"></dd>
            </dl>
        </div>

        <div class="tab-content leases unpadded">
            <div class="table-container">
                <table class="data-table">
                    <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Expiration</th>
                        <th>Pool</th>
                        <th>Hostname</th>
                        <th></th>
                    </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <div class="tab-content mappings unpadded">
            <div class="table-container">
                <button type="button" class="small create ">Create New Mapping</button>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>MAC Address</th>
                            <th>IP Address</th>
                            <th>&nbsp;</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <div class="scrollable">
            <div class="tab-content details">
                <fieldset class="primary">
                    <label class="primary">DHCP Name</label>
                    <div class="readonly"><%= name %></div>

                    <label class="primary" for="subnet<%= id %>">Subnet</label>
                    <div class="readonly"><%= subnet %></div>

                    <label class="primary" for="range-start<%= id %>">Range Start</label>
                    <div>
                        <input type="text" id="range-start<%= id %>" name="range-start" class="text-input" />
                    </div>

                    <label class="primary" for="range-stop<%= id %>">Range Stop</label>
                    <div>
                        <input type="text" id="range-stop<%= id %>" name="range-stop" class="text-input" />
                    </div>

                    <label class="primary" for="router<%= id %>">Router</label>
                    <div>
                        <input type="text" id="router<%= id %>" name="router" class="text-input" />
                    </div>

                    <label class="primary" for="unifi-controller<%= id %>">Unifi Controller</label>
                    <div>
                        <input type="text" id="unifi-controller<%= id %>" name="unifi-controller" class="text-input" />
                    </div>
                </fieldset>

                <fieldset class="primary">
                    <label class="primary" for="dns1<%= id %>">DNS 1</label>
                    <div>
                        <input type="text" id="dns1<%= id %>" name="dns1" class="text-input" />
                    </div>

                    <label class="primary" for="dns2<%= id %>">DNS 2</label>
                    <div>
                        <input type="text" id="dns2<%= id %>" name="dns2" class="text-input" />
                    </div>

                    <label class="primary" for="domain<%= id %>">Domain</label>
                    <div>
                        <input type="text" id="domain<%= id %>" name="domain" class="text-input" />
                    </div>

                    <label class="primary" for="lease<%= id %>">Lease Time</label>
                    <div>
                        <input type="text" id="lease<%= id %>" name="lease" class="text-input" /> seconds
                    </div>

                    <label class="primary" for="enabled<%= id %>">Enable</label>
                    <div>
                        <input type="checkbox" id="enabled<%= id %>" name="enabled" value="1" class="check-box-input" />
                    </div>
                </fieldset>

                <fieldset class="actions">
                    <button type="submit">Save</button>
                </fieldset>
            </div>
        </div>
		<div class="actions grouped">
			<div class="left">
				<button type="button" class="small delete">Delete</button>
			</div>
		</div>
	</form>
</script>

<script id="ServicesDhcpServerAddToStaticConfigTemplate" type="text/template">
    <form method="post" class="ui-form">
        <div class="scrollable">
            <div class="tab-content unpadded info">
                <div class="section form">
                    <fieldset class="primary">
                        <label class="primary required">IP Address</label>
                        <div>
                            <input type="text" id="name<%= id %>" class="text-input" name="ipaddress" />
                        </div>

                        <label class="primary required">Mac Address</label>
                        <div class="readonly" id="mac<%= id %>" name="macaddress" ><%= mac %></div>

                        <label class="primary required" for="name<%= id %>" >Name</label>
                        <div>
                            <input type="text" id="name<%= id %>" class="text-input" name="name" />
                        </div>
                    </fieldset>
                    <fieldset class="actions">
                        <button type="submit">Save</button>
                    </fieldset>
                </div>
            </div>
        </div>
    </form>
</script>

<script id="ServicesDhcpServerMappingConfigTemplate" type="text/template">
	<form method="post" class="ui-form">
		<div class="scrollable">
			<div class="tab-content unpadded info">
				<div class="section form">
					<fieldset class="primary">
						<label class="primary required">ID</label>
						<div class="readonly"><%= id %></div>

						<label class="primary required" for="macaddress<%= id %>">MAC Address</label>
						<div>
							<input type="text" id="macaddress<%= id %>" name="macaddress" class="text-input" />
						</div>

						<label class="primary required" for="ipaddress<%= id %>">IP Address</label>
						<div>
							<input type="text" id="ipaddress<%= id %>" name="ipaddress" class="text-input" />
						</div>
					</fieldset>

					<fieldset class="actions">
						<button type="submit">Save</button>
					</fieldset>
				</div>
			</div>
		</div>
	</form>
</script>

<script id="ServicesDhcpServerMappingCreateTemplate" type="text/template">
	<form method="post" class="ui-form">
		<div class="scrollable">
			<div class="tab-content unpadded info">
				<div class="section form">
					<fieldset class="primary">
						<label class="primary required" for="id<%= id %>">ID</label>
						<div>
							<input type="text" id="id<%= id %>" name="id" class="text-input" />
						</div>

						<label class="primary required" for="macaddress<%= id %>">MAC Address</label>
						<div>
							<input type="text" id="macaddress<%= id %>" name="macaddress" class="text-input" />
						</div>

						<label class="primary required" for="ipaddress<%= id %>">IP Address</label>
						<div>
							<input type="text" id="ipaddress<%= id %>" name="ipaddress" class="text-input" />
						</div>
					</fieldset>

					<fieldset class="actions">
						<button type="submit">Save</button>
					</fieldset>
				</div>
			</div>
		</div>
	</form>
</script>

<script id="ServicesDhcpServerRowDropDownButtonTemplate" type="text/template">
    <button type="button">Actions</button>
    <ul class="action-list">
        <li><a class="action-leases" href="#">View Leases</a></li>
        <li><a class="action-mappings" href="#">Configure Static Map</a></li>
        <li><a class="action-mappings-readonly" href="#">View Static Map</a></li>
        <li><a class="action-details" href="#">View Details</a></li>
        <li><a class="action-delete" href="#">Delete</a></li>
        <li><a class="action-status" href="#"></a></li>
    </ul>
</script>

<script id="ServicesDhcpServerLeasesRowDropDownButtonTemplate" type="text/template">
    <button type="button" class="add-to-static">Map Static IP</button>
</script>

<script id="ServicesDhcpServerMappingRowDropDownButtonTemplate" type="text/template">
    <button type="button">Actions</button>
    <ul class="action-list">
        <li><a class="action-config" href="#">Config</a></li>
        <li><a class="action-delete" href="#">Delete</a></li>
    </ul>
</script>

<script id="ServicesDnsDDnsTemplate" type="text/template">
	<form method="post" class="ui-form ddns"></form>
</script>

<script id="ServicesBlacklistDefaultTemplate" type="text/template">
	<div class="section-container service-form">
		<form method="post" class="ui-form blacklist">
			<fieldset class="primary interfaces">
				<legend>DNS Blacklist</legend>

				<label class="primary" for="cache-size">Cache Size</label>
				<div>
				    <input type="text" id="cache-size" name="cache-size" class="text-input" data-infotip="Number of DNS queries to cache" />
				</div>

				<div class="multiple interfaces">
					<label class="primary required">Interface</label>
					<div class="inputs">
						<div>
						    <select name="interface">
						    	<option value="">--</option>
						    </select>
						    <span class="other"><input type="text" name="other-interface" class="text-input"/></span>
						</div>
					</div>
				</div>
			</fieldset>

			<fieldset class="actions">
				<div>
					<button type="button" class="deleteDns">Delete</button>
					<button type="button" class="cancel">Cancel</button>
				    <button type="submit">Save</button>
				</div>
			</fieldset>
		</form>
	</div>

	<div class="section-container service-form ddns"></div>
</script>

<script id="ServicesDnsDefaultTemplate" type="text/template">
	<div class="section-container service-form">
		<form method="post" class="ui-form dns">
			<fieldset class="primary interfaces">
				<legend>DNS Forwarding</legend>

				<label class="primary" for="cache-size">Cache Size</label>
				<div>
				    <input type="text" id="cache-size" name="cache-size" class="text-input" data-infotip="Number of DNS queries to cache" />
				</div>

				<div class="multiple interfaces">
					<label class="primary required">Interface</label>
					<div class="inputs">
						<div>
						    <select name="interface">
						    	<option value="">--</option>
						    </select>
						    <span class="other"><input type="text" name="other-interface" class="text-input"/></span>
						</div>
					</div>
				</div>
			</fieldset>

			<fieldset class="actions">
				<div>
					<button type="button" class="deleteDns">Delete</button>
					<button type="button" class="cancel">Cancel</button>
				    <button type="submit">Save</button>
				</div>
			</fieldset>
		</form>
	</div>

	<div class="section-container service-form ddns"></div>
</script>

<script id="ServicesPppoeDefaultTemplate" type="text/template">
	<div class="section-container service-form">
		<form method="post" class="ui-form">
			<fieldset class="primary pppoe">
				<legend>PPPoE Server</legend>

				<label class="primary required" for="pppoe-client-ip-start">Client IP pool range start</label>
				<div>
				    <input type="text" id="pppoe-client-ip-start" name="client-ip-start" class="text-input" data-infotip="Begining IPv4 address for client pool.<br /><br />Example: <b>192.0.2.1</b>" />
				</div>

				<label class="primary required" for="pppoe-client-ip-stop">Client IP pool range stop</label>
				<div>
				    <input type="text" id="pppoe-client-ip-stop" name="client-ip-stop" class="text-input" data-infotip="End IPv4 address for client pool.  Must be within the same /24 as the range start.<br /><br />Example: <b>192.0.2.254</b>" />
				</div>

				<label class="primary required" for="pppoe-radius-server-ip">RADIUS server IP address</label>
				<div>
				    <input type="text" id="pppoe-radius-server-ip" name="radius-server-ip" class="text-input" data-infotip="IPv4 address of the RADIUS server<br /><br />Example: <b>192.0.2.1</b>" />
				</div>

				<label class="primary required" for="pppoe-radius-server-key">RADIUS server key</label>
				<div>
				    <input type="text" id="pppoe-radius-server-key" name="radius-server-key" class="text-input" data-infotip="Password key for RADIUS server" />
				</div>

				<label class="primary" for="pppoe-mtu">MTU</label>
				<div>
				    <input type="text" id="pppoe-mtu" name="mtu" class="text-input" />
				</div>

				<label class="primary" for="pppoe-dns1">DNS 1</label>
				<div>
				    <input type="text" id="pppoe-dns1" name="dns1" class="text-input" data-infotip="IPv4 address<br /><br />Example: <b>192.0.2.1</b>" />
				</div>

				<label class="primary" for="pppoe-dns2">DNS 2</label>
				<div>
				    <input type="text" id="pppoe-dns2" name="dns2" class="text-input" data-infotip="IPv4 address<br /><br />Example: <b>192.0.2.1</b>" />
				</div>

				<div class="multiple interfaces">
					<label class="primary required">Interface</label>
					<div class="inputs">
						<div>
						    <select name="interface">
						    	<option value="">--</option>
						    </select>
						</div>
					</div>
				</div>
			</fieldset>

			<fieldset class="actions">
				<div>
					<button type="button" class="delete">Delete</button>
					<button type="button" class="cancel">Cancel</button>
					<button type="submit">Save</button>
				</div>
			</fieldset>
		</form>
	</div>
</script>
<!-- End: Services -->
