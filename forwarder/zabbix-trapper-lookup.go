package forwarder

import (
	"context"
	"database/sql"
	"github.com/bangunindo/trap2json/helper"
	"github.com/bangunindo/trap2json/snmp"
	"github.com/georgysavva/scany/v2/sqlscan"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"sync"
	"time"
)

type QueryResult struct {
	IPOrDNS       string         `db:"ip_or_dns"`
	Hostname      string         `db:"hostname"`
	ProxyHostname sql.NullString `db:"proxy_hostname"`
}

type LookupResult struct {
	Server   *ProxyConf
	Hostname string
}

const hostCacheQuery70 = `
select case when i.useip = 1 then i.ip else i.dns end                    as ip_or_dns,
       h.host                                                            as hostname,
       coalesce(p.name, case when z.name = '' then null else z.name end) as proxy_hostname
from hosts h
         join interface i on i.hostid = h.hostid
         join items i2 on i2.hostid = h.hostid
         join ha_node z on z.status = 3
         left join proxy p on p.proxyid = h.proxyid
where i2.key_ = $1
  -- item type is Zabbix trapper
  and i2.type = 2
  -- host is active and monitored
  and h.status = 0
  -- ip of snmp interface
  and i.type = 2`

const hostCacheQuery60 = `
select case when i.useip = 1 then i.ip else i.dns end                     as ip_or_dns,
       h.host                                                             as hostname,
       coalesce(hp.host, case when z.name = '' then null else z.name end) as proxy_hostname
from hosts h
         join interface i on i.hostid = h.hostid
         join items i2 on i2.hostid = h.hostid
         join ha_node z on z.status = 3
         left join hosts hp on hp.hostid = h.proxy_hostid
where i2.key_ = $1
  -- item type is Zabbix trapper
  and i2.type = 2
  -- host is active and monitored
  and h.status = 0
  -- ip of snmp interface
  and i.type = 2`

const hostCacheQueryPre60 = `
select case when i.useip = 1 then i.ip else i.dns end as ip_or_dns,
       h.host                                         as hostname,
       hp.host                                        as proxy_hostname
from hosts h
         join interface i on i.hostid = h.hostid
         join items i2 on i2.hostid = h.hostid
         left join hosts hp on hp.hostid = h.proxy_hostid
where i2.key_ = $1
  -- item type is Zabbix trapper
  and i2.type = 2
  -- host is active and monitored
  and h.status = 0
  -- ip of snmp interface
  and i.type = 2`

type ZabbixLookup struct {
	conf       *ZabbixTrapperConfig
	cacheMutex *sync.RWMutex
	logger     zerolog.Logger
	ctx        context.Context

	cacheByAddress  map[string]*LookupResult
	cacheByHostname map[string]*LookupResult
}

func (z *ZabbixLookup) refresh() {
	z.logger.Info().Msg("starting background cache refresh")
	now := time.Now()
	defer func() {
		dur := time.Since(now)
		z.logger.Info().Str("duration", dur.String()).Msg("background cache refresh done")
	}()
	if driver, dsn, err := helper.ParseDSN(z.conf.Advanced.DBUrl); err != nil {
		z.logger.Warn().Err(err).Msg("failed reading db_url")
	} else {
		db, err := sql.Open(driver, dsn)
		if err != nil {
			z.logger.Warn().Err(err).Msg("failed initializing db")
			return
		}
		defer db.Close()
		ctx, cancel := context.WithTimeout(z.ctx, z.conf.Advanced.DBQueryTimeout.Duration)
		defer cancel()
		err = db.PingContext(ctx)
		if err != nil {
			z.logger.Warn().Err(err).Msg("failed connecting to db")
			return
		}
		var zbxVersion int
		err = sqlscan.Get(ctx, db, &zbxVersion, "select mandatory from dbversion")
		if err != nil {
			z.logger.Warn().Err(err).Msg("cannot determine zabbix version")
			return
		}
		var results []QueryResult
		switch {
		case zbxVersion >= 7000000:
			err = sqlscan.Select(ctx, db, &results, hostCacheQuery70, z.conf.ItemKey)
		case zbxVersion >= 6000000:
			err = sqlscan.Select(ctx, db, &results, hostCacheQuery60, z.conf.ItemKey)
		case zbxVersion < 6000000:
			err = sqlscan.Select(ctx, db, &results, hostCacheQueryPre60, z.conf.ItemKey)
		default:
			z.logger.Error().Msgf("unexpected error, unsupported version %d", zbxVersion)
			return
		}
		if err != nil {
			z.logger.Warn().Err(err).Msg("failed executing lookup query")
			return
		}
		cacheByAddress := make(map[string]*LookupResult)
		cacheByHostname := make(map[string]*LookupResult)
		for _, r := range results {
			lookupResult := LookupResult{
				Hostname: r.Hostname,
			}
			if proxy, ok := z.conf.Advanced.getProxy(r.ProxyHostname.String); ok && r.ProxyHostname.Valid {
				lookupResult.Server = &proxy
			}
			cacheByAddress[r.IPOrDNS] = &lookupResult
			cacheByHostname[r.Hostname] = &lookupResult
		}
		z.cacheMutex.Lock()
		z.cacheByAddress = cacheByAddress
		z.cacheByHostname = cacheByHostname
		z.cacheMutex.Unlock()
	}
}

func (z *ZabbixLookup) lookupByAddress(addr string) (LookupResult, error) {
	z.cacheMutex.RLock()
	defer z.cacheMutex.RUnlock()
	if r, ok := z.cacheByAddress[addr]; ok {
		return *r, nil
	} else {
		return LookupResult{}, errors.New("address lookup failed")
	}
}

func (z *ZabbixLookup) lookupByHostname(host string) (LookupResult, error) {
	z.cacheMutex.RLock()
	defer z.cacheMutex.RUnlock()
	if r, ok := z.cacheByHostname[host]; ok {
		return *r, nil
	} else {
		return LookupResult{}, errors.New("host lookup failed")
	}
}

func (z *ZabbixLookup) Lookup(m *snmp.Message, strategy LookupStrategy) (LookupResult, error) {
	if z.conf.Advanced != nil {
		switch strategy {
		case LookupFromOID:
			for _, v := range m.Payload.Values {
				if v.HasOIDPrefix(z.conf.OIDLookup) {
					if vStr, ok := v.Value.(string); ok {
						return z.lookupByHostname(vStr)
					}
				}
			}
		case LookupFromAgentAddress:
			if m.Payload.AgentAddress != nil {
				return z.lookupByAddress(*m.Payload.AgentAddress)
			}
		case LookupFromSourceAddress:
			if m.Payload.SrcAddress != "" {
				return z.lookupByAddress(m.Payload.SrcAddress)
			}
		}
	} else {
		switch strategy {
		case LookupFromOID:
			for _, v := range m.Payload.Values {
				if v.HasOIDPrefix(z.conf.OIDLookup) {
					if vStr, ok := v.Value.(string); ok {
						return LookupResult{
							Hostname: vStr,
						}, nil
					}
				}
			}
		case LookupFromAgentAddress:
			if m.Payload.AgentAddress != nil {
				return LookupResult{
					Hostname: *m.Payload.AgentAddress,
				}, nil
			}
		case LookupFromSourceAddress:
			if m.Payload.SrcAddress != "" {
				return LookupResult{
					Hostname: m.Payload.SrcAddress,
				}, nil
			}
		}
	}
	return LookupResult{}, errors.New("lookup failed")
}

func (z *ZabbixLookup) Refresh() {
	for {
		select {
		case <-time.After(z.conf.Advanced.DBRefreshInterval.Duration):
			z.refresh()
		case <-z.ctx.Done():
			return
		}
	}
}

func NewZabbixLookup(
	c *ZabbixTrapperConfig,
	logger zerolog.Logger,
	ctx context.Context,
) *ZabbixLookup {
	zLookup := &ZabbixLookup{
		conf:            c,
		cacheMutex:      new(sync.RWMutex),
		logger:          logger,
		ctx:             ctx,
		cacheByAddress:  make(map[string]*LookupResult),
		cacheByHostname: make(map[string]*LookupResult),
	}
	if c.Advanced != nil {
		c.Advanced.initProxyMap()
		zLookup.refresh()
		go zLookup.Refresh()
	}
	return zLookup
}
