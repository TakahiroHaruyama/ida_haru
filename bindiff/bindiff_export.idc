#include <idc.idc>
static main()
{
    ChangeConfig("ABANDON_DATABASE=YES");
    Batch(0);
    Wait();
    //RunPlugin("binexport11", 2 );
    //Exit( 1 - RunPlugin("zynamics_binexport_9", 2 ));
    //Exit( 1 - RunPlugin("zynamics_binexport_8", 2 ));
    //Exit( 1 - RunPlugin("binexport10", 2 ));
    //Exit( 1 - RunPlugin("binexport11", 2 ));
    //RunPlugin("binexport12_ida", 2 );
    Exit( 1 - RunPlugin("binexport12_ida", 2 ));
}
