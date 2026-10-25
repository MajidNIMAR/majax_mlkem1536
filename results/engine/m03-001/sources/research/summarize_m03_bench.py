"""Check all preregistered P01 observations and summarize without filtering."""
import argparse,gzip,json,math,statistics
from pathlib import Path

def summarize(rows):
    groups={}
    for row in rows:
        key=(row['engine'],row['operation'],row['series'])
        if row['engine'] not in ('R1','ML-KEM-1024') or row['operation'] not in ('keygen','encaps','decaps') or row['series'] not in range(5):
            raise ValueError('unknown measurement group')
        if type(row['nanoseconds']) is not int or row['nanoseconds']<=0:raise ValueError('invalid duration')
        group=groups.setdefault(key,{})
        i=row['iteration']
        if type(i) is not int or i not in range(1000) or i in group:raise ValueError('invalid or duplicate observation')
        group[i]=row['nanoseconds']
    if len(groups)!=30 or any(len(g)!=1000 for g in groups.values()):raise ValueError('incomplete P01 dataset')
    def stats(values):
        values=sorted(values)
        return dict(count=len(values),median_ns=statistics.median(values),p95_ns=values[math.ceil(.95*len(values))-1],
            minimum_ns=values[0],maximum_ns=values[-1],mean_ns=statistics.mean(values))
    panels=[]
    for engine in ('R1','ML-KEM-1024'):
        for operation in ('keygen','encaps','decaps'):
            panels.append(dict(engine=engine,operation=operation,
                series=[dict(series=i,**stats(groups[engine,operation,i].values())) for i in range(5)],
                aggregate=stats([v for i in range(5) for v in groups[engine,operation,i].values()])))
    return dict(observations=30000,warmup_per_series_and_function=100,series_per_function=5,
        measurements_per_series=1000,percentile='nearest rank ceil(0.95*N)',outliers_removed=0,
        output_drop_in_timed_region=False,system_randomness_in_keygen_and_encaps=True,panels=panels,
        comparable_optimization=False,optimization_note='R1 schoolbook; RustCrypto ML-KEM-1024 NTT')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('input',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args()
    opener=gzip.open if args.input.suffix=='.gz' else open
    with opener(args.input,'rt',encoding='utf-8') as stream:result=summarize([json.loads(line) for line in stream])
    with args.output.open('x',encoding='utf-8',newline='\n') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
