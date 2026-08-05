import { Cpu, Globe, Link2, FileCode, Server, Map, Network } from 'lucide-react';
import type { ReconResult } from '@/lib/types';

interface ReconPanelProps {
  recon: ReconResult;
}

export function ReconPanel({ recon }: ReconPanelProps) {
  return (
    <div className="space-y-4">
      {/* Technologies */}
      <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-5 backdrop-blur">
        <div className="flex items-center gap-2 mb-3">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">Technology Stack ({recon.technologies.length})</h3>
        </div>
        {recon.technologies.length === 0 ? (
          <p className="text-sm text-slate-500">No technologies detected.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {recon.technologies.map((tech, i) => (
              <div key={i} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/50 border border-slate-700/40">
                <span className={`w-1.5 h-1.5 rounded-full ${tech.confidence === 'certain' ? 'bg-emerald-400' : tech.confidence === 'high' ? 'bg-cyan-400' : 'bg-yellow-400'}`} />
                <span className="text-sm text-slate-300 font-medium">{tech.name}</span>
                {tech.version && <span className="text-xs text-slate-500 font-mono">{tech.version}</span>}
                <span className="text-[10px] text-slate-600">{tech.category}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* DNS Info */}
      <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-5 backdrop-blur">
        <div className="flex items-center gap-2 mb-3">
          <Network className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">DNS Information</h3>
        </div>
        <div className="grid sm:grid-cols-3 gap-3">
          <DnsCard icon={<Globe className="w-3.5 h-3.5" />} label="Hostname" value={recon.dnsInfo.hostname} />
          <DnsCard icon={<Server className="w-3.5 h-3.5" />} label="IP Addresses" value={recon.dnsInfo.ips.length ? `${recon.dnsInfo.ips.length} found` : 'Not resolved'} />
          <DnsCard icon={<FileCode className="w-3.5 h-3.5" />} label="TXT Records" value={`${recon.dnsInfo.txtRecords.length} found`} />
        </div>
        {recon.dnsInfo.ips.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {recon.dnsInfo.ips.slice(0, 5).map((ip, i) => (
              <span key={i} className="text-xs font-mono text-slate-400 px-2 py-1 rounded bg-slate-800/50 border border-slate-700/30">{ip}</span>
            ))}
          </div>
        )}
      </div>

      {/* Endpoints */}
      <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-5 backdrop-blur">
        <div className="flex items-center gap-2 mb-3">
          <Map className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">Discovered Endpoints ({recon.endpoints.length})</h3>
        </div>
        {recon.endpoints.length === 0 ? (
          <p className="text-sm text-slate-500">No endpoints discovered.</p>
        ) : (
          <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
            {recon.endpoints.slice(0, 30).map((ep) => (
              <div key={ep.id} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/30 hover:bg-slate-800/50 transition">
                <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${ep.method === 'POST' ? 'bg-orange-500/20 text-orange-400' : 'bg-cyan-500/20 text-cyan-400'}`}>
                  {ep.method}
                </span>
                <span className="text-xs text-slate-400 font-mono truncate flex-1">{ep.url}</span>
                {ep.authRequired && <span className="text-[10px] text-red-400/70 flex-shrink-0">AUTH</span>}
                {ep.parameters.length > 0 && <span className="text-[10px] text-slate-600 flex-shrink-0">{ep.parameters.length} params</span>}
              </div>
            ))}
            {recon.endpoints.length > 30 && <p className="text-xs text-slate-600 text-center pt-2">+ {recon.endpoints.length - 30} more...</p>}
          </div>
        )}
      </div>

      {/* JavaScript Resources */}
      <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-5 backdrop-blur">
        <div className="flex items-center gap-2 mb-3">
          <Link2 className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">JavaScript Resources ({recon.javascriptResources.length})</h3>
        </div>
        {recon.javascriptResources.length === 0 ? (
          <p className="text-sm text-slate-500">No JavaScript resources found.</p>
        ) : (
          <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
            {recon.javascriptResources.slice(0, 15).map((js, i) => (
              <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/30">
                <FileCode className="w-3 h-3 text-slate-600 flex-shrink-0" />
                <span className="text-xs text-slate-400 font-mono truncate">{js}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function DnsCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="bg-slate-800/40 rounded-xl p-3 border border-slate-700/30">
      <div className="text-xs text-slate-500 mb-1 flex items-center gap-1.5">{icon}{label}</div>
      <div className="text-sm font-semibold text-slate-200 font-mono truncate">{value}</div>
    </div>
  );
}
