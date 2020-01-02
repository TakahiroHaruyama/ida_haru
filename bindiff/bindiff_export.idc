#include <idc.idc>
static main()
{
    Batch(0);
    Wait();
    //RunPlugin("zynamics_binexport_9", 2 );
    //Exit( 1 - RunPlugin("zynamics_binexport_9", 2 ));
    //Exit( 1 - RunPlugin("zynamics_binexport_8", 2 ));
    //Exit( 1 - RunPlugin("binexport10", 2 ));
    Exit( 1 - RunPlugin("binexport11", 2 ));
}
